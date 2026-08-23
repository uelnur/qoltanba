package challenge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// nonceBytes is the size of an issued nonce: 256 bits of randomness, so a nonce
// can be neither guessed nor collided within its short lifetime.
const nonceBytes = 32

// defaultTTL bounds how long an unsigned challenge stays usable. Short by design:
// the window is the exposure, and a user who took too long simply asks again.
const defaultTTL = 5 * time.Minute

// SigningForm names what the client must produce over the nonce. Only detached
// CMS is issued today; naming it on the wire keeps the contract explicit.
const SigningForm = "CMS-detached"

// Verifier is the narrow slice of the domain this package depends on: verify a
// signature and check certificate revocation. *core.Service satisfies it, and a
// fake satisfies it in tests, so the flow is exercised without Kalkan.
type Verifier interface {
	Verify(ctx context.Context, in core.VerifyInput) (core.VerifyOutput, error)
	Validate(ctx context.Context, in core.ValidateInput) (core.ValidateOutput, error)
}

// Config parameterizes a Service.
type Config struct {
	// TTL is how long an issued challenge remains usable. Zero uses defaultTTL.
	TTL time.Duration
	// RequireOCSP makes an unconfirmed revocation status fail the confirmation.
	// Off by default: revocation checking needs network access to the responder,
	// and a caller confirming a low-stakes action may not want that dependency.
	RequireOCSP bool
}

// Service issues and confirms challenges.
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

// New builds the service over a verifier and a store.
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

// IssueRequest asks for a nonce to sign. Purpose labels what signing it will
// mean; Meta is echoed back on confirmation.
type IssueRequest struct {
	Purpose string            `json:"purpose,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
}

// IssueResponse tells the client what to sign.
type IssueResponse struct {
	ChallengeID string `json:"challengeId"`
	Data        string `json:"data"` // base64 nonce to sign
	Alg         string `json:"alg"`  // signing form expected
	ExpiresIn   int    `json:"expiresIn"`
	Purpose     string `json:"purpose,omitempty"`
}

// ConfirmRequest submits the user's detached signature over the nonce.
type ConfirmRequest struct {
	ChallengeID string `json:"challengeId"`
	Signature   []byte `json:"signature"`
	// CheckRevocation forces a revocation check for this confirmation even when
	// the service default is off.
	CheckRevocation bool `json:"checkRevocation,omitempty"`
}

// ConfirmResponse reports who signed the challenge and for what. Confirmed is the
// single flag a caller acts on; the identity fields say who to attribute the
// action to.
type ConfirmResponse struct {
	Confirmed   bool              `json:"confirmed"`
	Purpose     string            `json:"purpose,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	ConfirmedAt time.Time         `json:"confirmedAt"`
	Signer      *core.Claims      `json:"signer,omitempty"`
	Certificate *core.Certificate `json:"certificate,omitempty"`
	// Revoked reports the signer certificate's revocation status when it was
	// checked; nil means the check did not run.
	Revoked *bool `json:"revoked,omitempty"`
}

// Issue creates a single-use nonce bound to a purpose.
func (s *Service) Issue(ctx context.Context, req IssueRequest) (IssueResponse, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return IssueResponse{}, err
	}
	id, err := randID()
	if err != nil {
		return IssueResponse{}, err
	}
	now := s.now()
	ch := &Challenge{
		ID:        id,
		Nonce:     nonce,
		Purpose:   req.Purpose,
		Meta:      req.Meta,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.TTL),
	}
	if err := s.store.Create(ctx, ch); err != nil {
		return IssueResponse{}, err
	}
	return IssueResponse{
		ChallengeID: id,
		Data:        base64.StdEncoding.EncodeToString(nonce),
		Alg:         SigningForm,
		ExpiresIn:   int(s.cfg.TTL.Seconds()),
		Purpose:     req.Purpose,
	}, nil
}

// Confirm consumes the challenge and verifies the detached signature over its
// nonce. Consuming first is deliberate: a replayed id is rejected before any
// crypto work, and a failed verification still burns the challenge, so a signature
// cannot be brute-forced against one nonce.
func (s *Service) Confirm(ctx context.Context, req ConfirmRequest) (ConfirmResponse, error) {
	ch, err := s.store.Consume(ctx, req.ChallengeID)
	if err != nil {
		return ConfirmResponse{}, err
	}
	now := s.now()
	if !ch.ExpiresAt.After(now) {
		return ConfirmResponse{}, ErrExpired
	}

	out, err := s.verifier.Verify(ctx, core.VerifyInput{
		Format:        core.FormatCMS,
		Signature:     req.Signature,
		Data:          ch.Nonce,
		Detached:      true,
		CheckCertTime: true,
		ExtractClaims: true,
	})
	if err != nil {
		return ConfirmResponse{}, fmt.Errorf("verify challenge signature: %w", err)
	}
	if !out.Valid || len(out.Signers) == 0 {
		return ConfirmResponse{Purpose: ch.Purpose, Meta: ch.Meta, ConfirmedAt: now}, nil
	}

	signer := out.Signers[0]
	resp := ConfirmResponse{
		Confirmed:   true,
		Purpose:     ch.Purpose,
		Meta:        ch.Meta,
		ConfirmedAt: now,
		Signer:      signer.Claims,
		Certificate: &signer.Certificate,
	}
	if s.cfg.RequireOCSP || req.CheckRevocation {
		revoked, err := s.checkRevocation(ctx, signer.Certificate.PEM)
		if err != nil {
			// A revocation check the caller asked for and that could not run must not
			// be reported as "not revoked": the confirmation fails instead.
			return ConfirmResponse{}, err
		}
		resp.Revoked = &revoked
		if revoked {
			resp.Confirmed = false
		}
	}
	return resp, nil
}

func (s *Service) checkRevocation(ctx context.Context, certPEM []byte) (bool, error) {
	out, err := s.verifier.Validate(ctx, core.ValidateInput{
		Cert: certPEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
	})
	if err != nil {
		return false, fmt.Errorf("revocation check: %w", err)
	}
	if out.Status.LibError != nil && !out.Status.Revoked {
		return false, fmt.Errorf("revocation check inconclusive: %s", out.Status.LibError.Message)
	}
	return out.Status.Revoked, nil
}

// Reap deletes expired challenges. The store keeps entries until then so a late
// confirmation reports "expired" rather than the misleading "not found".
func (s *Service) Reap(ctx context.Context) (int, error) { return s.store.Reap(ctx, s.now()) }

// Start runs the background reaper until ctx ends. Expired challenges are already
// refused on confirmation; reaping only keeps the store from growing.
func (s *Service) Start(ctx context.Context) {
	interval := s.cfg.TTL
	if interval > time.Minute {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = s.Reap(ctx)
			}
		}
	}()
}

// Active reports how many challenges are outstanding, for a metrics gauge.
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
