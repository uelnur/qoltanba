// Package multisign coordinates "we are still waiting for signer B": a document
// that several people must sign, tracked until it is complete.
//
// The crypto primitive already exists — co-signing adds a signerInfo to a
// container. What a document-flow application has to build on top is the waiting:
// who still owes a signature, is this new container really the previous one plus
// one authorized signer, and is the whole thing done. That bookkeeping is the same
// everywhere, so it lives here instead of in every consumer.
//
// Signing itself happens where the key is — the service never sees a private key.
// A participant fetches the current container, co-signs it with their own tooling
// and submits the result; this package verifies and accepts it.
package multisign

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Status is the session lifecycle state.
type Status string

const (
	StatusPending  Status = "pending"  // still waiting for signatures
	StatusComplete Status = "complete" // every required signer has signed
	StatusExpired  Status = "expired"  // the deadline passed while incomplete
)

// Errors of the flow.
var (
	ErrNotFound      = errors.New("multisign: session not found")
	ErrSessionClosed = errors.New("multisign: session is already complete or expired")
	ErrNoNewSigner   = errors.New("multisign: the submitted container adds no new signer")
	ErrLostSigner    = errors.New("multisign: the submitted container drops an existing signature")
	ErrNotInvited    = errors.New("multisign: the signer is not among those required")
	ErrAlreadySigned = errors.New("multisign: this signer already signed")
	ErrInvalid       = errors.New("multisign: the submitted container does not verify")
)

// Verifier is the slice of the domain this package needs.
type Verifier interface {
	Verify(ctx context.Context, in core.VerifyInput) (core.VerifyOutput, error)
}

// Required identifies one participant who must sign. At least one field must be
// set; a signer matches when every set field matches theirs. Matching on identity
// rather than on order is deliberate: signature indexes do not carry signing
// order, and they differ between CMS and XML.
type Required struct {
	IIN  string `json:"iin,omitempty"`
	BIN  string `json:"bin,omitempty"`
	Role string `json:"role,omitempty"`
	// Label names the participant for humans ("Директор", "Бухгалтер").
	Label string `json:"label,omitempty"`
}

func (r Required) empty() bool { return r.IIN == "" && r.BIN == "" && r.Role == "" }

// matches reports whether a signer satisfies this requirement.
func (r Required) matches(s core.ReportSigner) bool {
	if r.IIN != "" && r.IIN != s.IIN {
		return false
	}
	if r.BIN != "" && r.BIN != s.BIN {
		return false
	}
	if r.Role != "" && !hasRole(s.Roles, r.Role) {
		return false
	}
	return true
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// Signature records one collected signature.
type Signature struct {
	IIN      string    `json:"iin,omitempty"`
	BIN      string    `json:"bin,omitempty"`
	Name     string    `json:"name,omitempty"`
	Roles    []string  `json:"roles,omitempty"`
	SignedAt time.Time `json:"signedAt"`
	// Satisfies is the index in Required this signature fulfilled, or -1 when the
	// session accepts any signers up to a count.
	Satisfies int `json:"satisfies"`
}

// Session is one document awaiting signatures.
type Session struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	// Format of the container being built (cms or xml).
	Format core.SignatureFormat `json:"format"`
	// Detached says the content is carried separately from the signature.
	Detached bool `json:"detached"`
	// Document is the content being signed; empty for an attached container, where
	// the content lives inside Container.
	Document []byte `json:"document,omitempty"`
	// Container is the signature as it stands: empty until the first participant
	// signs, then the growing co-signed container.
	Container []byte `json:"container,omitempty"`

	Required   []Required  `json:"required,omitempty"`
	MinSigners int         `json:"minSigners,omitempty"`
	Collected  []Signature `json:"collected"`

	Subject   string    `json:"subject,omitempty"` // human label of the document
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Remaining lists the requirements still unmet.
func (s *Session) Remaining() []Required {
	var out []Required
	for i, req := range s.Required {
		if !s.satisfied(i) {
			out = append(out, req)
		}
	}
	return out
}

func (s *Session) satisfied(idx int) bool {
	for _, c := range s.Collected {
		if c.Satisfies == idx {
			return true
		}
	}
	return false
}

// complete reports whether the session's requirements are met.
func (s *Session) complete() bool {
	if len(s.Required) > 0 {
		return len(s.Remaining()) == 0
	}
	return len(s.Collected) >= s.MinSigners
}

// Store persists sessions between requests. Sessions outlive a request by design —
// waiting for a colleague takes days — so a durable store is the realistic choice
// for anything but a demo.
type Store interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	Save(ctx context.Context, s *Session) error
	Delete(ctx context.Context, id string) error
	Len() int
	Close() error
}

// Config parameterizes a Service.
type Config struct {
	// TTL is how long a session waits before it expires. Zero uses 7 days: signing
	// rounds in a document flow run in days, not minutes.
	TTL time.Duration
}

// Service coordinates the sessions.
type Service struct {
	verifier Verifier
	store    Store
	cfg      Config
	now      func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

const defaultTTL = 7 * 24 * time.Hour

// New builds the service.
func New(v Verifier, store Store, cfg Config, opts ...Option) *Service {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	s := &Service{verifier: v, store: store, cfg: cfg, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// CreateRequest opens a session.
type CreateRequest struct {
	Format   core.SignatureFormat `json:"format,omitempty"`
	Detached bool                 `json:"detached,omitempty"`
	Document []byte               `json:"document,omitempty"`
	// Container seeds the session with signatures already collected elsewhere.
	Container []byte     `json:"container,omitempty"`
	Required  []Required `json:"required,omitempty"`
	// MinSigners accepts any signers up to this count, for "any two directors"
	// rules where the participants are not known up front. Ignored when Required
	// is set.
	MinSigners int    `json:"minSigners,omitempty"`
	Subject    string `json:"subject,omitempty"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

// Create opens a session for a document.
func (s *Service) Create(ctx context.Context, req CreateRequest) (*Session, error) {
	if len(req.Document) == 0 && len(req.Container) == 0 {
		return nil, fmt.Errorf("multisign: document or container is required")
	}
	if len(req.Required) == 0 && req.MinSigners <= 0 {
		return nil, fmt.Errorf("multisign: either required signers or minSigners must be set")
	}
	for i, r := range req.Required {
		if r.empty() {
			return nil, fmt.Errorf("multisign: required[%d] identifies nobody (set iin, bin or role)", i)
		}
	}
	format := req.Format
	if format == "" {
		format = core.FormatCMS
	}
	if !format.Valid() {
		return nil, fmt.Errorf("multisign: unknown format %q", format)
	}

	id, err := randID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	ttl := s.cfg.TTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	sess := &Session{
		ID: id, Status: StatusPending, Format: format, Detached: req.Detached,
		Document: req.Document, Container: req.Container,
		Required: req.Required, MinSigners: req.MinSigners, Subject: req.Subject,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	// A seeded container counts what it already carries, so a session resumed from
	// signatures gathered elsewhere does not ask for them again.
	if len(req.Container) > 0 {
		signers, err := s.signersOf(ctx, sess, req.Container)
		if err != nil {
			return nil, err
		}
		for _, sig := range signers {
			sess.Collected = append(sess.Collected, s.record(sess, sig, now))
		}
		if sess.complete() {
			sess.Status = StatusComplete
		}
	}
	if err := s.store.Create(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// Get returns a session, expiring it when its deadline passed.
func (s *Service) Get(ctx context.Context, id string) (*Session, error) {
	sess, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if sess.Status == StatusPending && !sess.ExpiresAt.After(s.now()) {
		sess.Status = StatusExpired
		_ = s.store.Save(ctx, sess)
	}
	return sess, nil
}

// Submit accepts the container as it stands after another participant co-signed
// it. The container is verified, and the new signer must be one the session was
// waiting for — otherwise a passer-by could complete someone else's document.
func (s *Service) Submit(ctx context.Context, id string, container []byte) (*Session, error) {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if sess.Status != StatusPending {
		return nil, ErrSessionClosed
	}

	signers, err := s.signersOf(ctx, sess, container)
	if err != nil {
		return nil, err
	}
	// Every signature already collected must still be there. Counting alone would
	// miss a container that swaps one signer for another, which is how a
	// participant could quietly drop a colleague's signature.
	if !containsAll(signers, sess.Collected) {
		return nil, ErrLostSigner
	}

	now := s.now()
	added := 0
	for _, sig := range signers {
		if s.alreadyCollected(sess, sig) {
			continue
		}
		rec := s.record(sess, sig, now)
		if len(sess.Required) > 0 && rec.Satisfies < 0 {
			// Either this person was not invited, or their slot is already filled.
			if s.matchesAnyRequirement(sess, sig) {
				return nil, ErrAlreadySigned
			}
			return nil, ErrNotInvited
		}
		sess.Collected = append(sess.Collected, rec)
		added++
	}
	if added == 0 {
		return nil, ErrNoNewSigner
	}

	sess.Container = container
	if sess.complete() {
		sess.Status = StatusComplete
	}
	if err := s.store.Save(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// containsAll reports whether every previously collected signature is present
// among the container's signers.
func containsAll(signers []core.ReportSigner, collected []Signature) bool {
	present := make(map[string]struct{}, len(signers))
	for _, s := range signers {
		present[identityOf(s.IIN, s.BIN, s.Name)] = struct{}{}
	}
	for _, c := range collected {
		if _, ok := present[identityOf(c.IIN, c.BIN, c.Name)]; !ok {
			return false
		}
	}
	return true
}

// signersOf verifies the container and returns its signers. A container that does
// not verify is rejected outright: collecting an invalid signature would make the
// session's completion meaningless.
func (s *Service) signersOf(ctx context.Context, sess *Session, container []byte) ([]core.ReportSigner, error) {
	out, err := s.verifier.Verify(ctx, core.VerifyInput{
		Format:        sess.Format,
		Signature:     container,
		Data:          sess.Document,
		Detached:      sess.Detached,
		InputPEM:      strings.HasPrefix(string(container), "-----BEGIN"),
		CheckCertTime: true,
		ExtractClaims: true,
		Report:        true,
	})
	if err != nil {
		return nil, err
	}
	if !out.Valid || out.Report == nil {
		return nil, ErrInvalid
	}
	return out.Report.Signers, nil
}

// record builds the collected-signature entry, resolving which requirement it
// fulfills (-1 when the session only counts signatures).
func (s *Service) record(sess *Session, sig core.ReportSigner, now time.Time) Signature {
	signedAt := now
	if sig.SignedAt != nil {
		signedAt = *sig.SignedAt
	}
	rec := Signature{
		IIN: sig.IIN, BIN: sig.BIN, Name: sig.Name, Roles: sig.Roles,
		SignedAt: signedAt, Satisfies: -1,
	}
	for i, req := range sess.Required {
		if !sess.satisfied(i) && req.matches(sig) {
			rec.Satisfies = i
			break
		}
	}
	return rec
}

func (s *Service) alreadyCollected(sess *Session, sig core.ReportSigner) bool {
	for _, c := range sess.Collected {
		if identityOf(c.IIN, c.BIN, c.Name) == identityOf(sig.IIN, sig.BIN, sig.Name) {
			return true
		}
	}
	return false
}

func (s *Service) matchesAnyRequirement(sess *Session, sig core.ReportSigner) bool {
	for _, req := range sess.Required {
		if req.matches(sig) {
			return true
		}
	}
	return false
}

// identityOf keys a signer. IIN identifies a person; a legal-person certificate
// without one falls back to BIN plus name, which is what distinguishes two
// officers of the same organization.
func identityOf(iin, bin, name string) string {
	if iin != "" {
		return "iin:" + iin
	}
	return "bin:" + bin + "|" + name
}

// Cancel removes a session.
func (s *Service) Cancel(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }

// Active reports how many sessions are stored, for a metrics gauge.
func (s *Service) Active() int { return s.store.Len() }

// Close releases the store.
func (s *Service) Close() error { return s.store.Close() }

func randID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
