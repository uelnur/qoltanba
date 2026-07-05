package qr

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// appPathPrefix is the public app-facing route the QR points at for self-hosted
// profiles. eGov Mobile GETs the data-to-sign from base+appPathPrefix+id and POSTs
// the signature back to the same URL. The unguessable id is the capability token.
const appPathPrefix = "/qr/a/"

// Config tunes the orchestrator. Zero values fall back to safe defaults.
type Config struct {
	DefaultProfile Profile
	DefaultMode    Mode
	TTL            time.Duration // session lifetime (default 5m)
	ReapInterval   time.Duration // expired-session sweep cadence (default min(TTL, 1m))
	RequireOCSP    bool          // require a good OCSP status before accepting a signature
}

func (c Config) withDefaults() Config {
	if c.DefaultProfile == "" {
		c.DefaultProfile = ProfileAgnostic
	}
	if c.DefaultMode == "" {
		c.DefaultMode = ModeSign
	}
	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}
	if c.ReapInterval <= 0 {
		c.ReapInterval = c.TTL
		if c.ReapInterval > time.Minute {
			c.ReapInterval = time.Minute
		}
	}
	return c
}

// Webhook delivers a terminal session View to a consumer's callback URL. The HTTP
// POST lives in the transport wiring; this is the injection seam (like jobs).
type Webhook func(ctx context.Context, url string, v View)

// Orchestrator runs the QR session lifecycle over a set of profiles. It owns no
// crypto: verification is delegated to the domain Verifier and token minting to the
// TokenIssuer, so it is tested without Kalkan.
type Orchestrator struct {
	verifier Verifier
	issuer   TokenIssuer // nil disables auth mode
	store    SessionStore
	profiles map[Profile]Profiler
	cfg      Config
	webhook  Webhook
	log      *slog.Logger
	now      func() time.Time
}

// Option configures an Orchestrator.
type Option func(*Orchestrator)

// WithLogger sets the structured logger (nil-safe).
func WithLogger(l *slog.Logger) Option {
	return func(o *Orchestrator) {
		if l != nil {
			o.log = l
		}
	}
}

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(o *Orchestrator) { o.now = now } }

// WithWebhook enables best-effort terminal delivery to a session's callback URL.
func WithWebhook(w Webhook) Option { return func(o *Orchestrator) { o.webhook = w } }

// WithTokenIssuer enables auth mode by wiring the OIDC token issuer.
func WithTokenIssuer(t TokenIssuer) Option { return func(o *Orchestrator) { o.issuer = t } }

// New builds an Orchestrator. profiles maps each enabled Profile to its impl.
func New(v Verifier, store SessionStore, profiles map[Profile]Profiler, cfg Config, opts ...Option) *Orchestrator {
	o := &Orchestrator{
		verifier: v,
		store:    store,
		profiles: profiles,
		cfg:      cfg.withDefaults(),
		log:      slog.Default(),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Create starts a session: mints the id, builds the QR via the selected profile,
// and stores it. publicBase is the externally reachable base URL (behind the
// consumer's proxy) used to build the app-facing URL for self-hosted profiles.
func (o *Orchestrator) Create(ctx context.Context, req CreateRequest, publicBase string) (CreateResponse, error) {
	mode := req.Mode
	if mode == "" {
		mode = o.cfg.DefaultMode
	}
	if !mode.valid() {
		return CreateResponse{}, ErrUnsupportedMode
	}
	if mode == ModeAuth && o.issuer == nil {
		return CreateResponse{}, ErrAuthUnavailable
	}
	profile := req.Profile
	if profile == "" {
		profile = o.cfg.DefaultProfile
	}
	impl, ok := o.profiles[profile]
	if !ok {
		return CreateResponse{}, ErrUnsupportedProfile
	}

	id, err := newID()
	if err != nil {
		return CreateResponse{}, err
	}
	format := req.Format
	if format == "" {
		format = core.FormatCMS
	}
	signMethod := req.SignMethod
	if signMethod == "" {
		signMethod = "CMS_SIGN_ONLY"
	}
	ttl := o.cfg.TTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	now := o.now()
	sess := &Session{
		ID: id, Mode: mode, Profile: profile, SignMethod: signMethod, Format: format,
		Detached: req.Detached, Documents: req.Documents, Description: req.Description,
		ClientID: req.ClientID, ClientNonce: req.Nonce, State: req.State, CallbackURL: req.CallbackURL,
		Status: StatusPending, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}

	if mode == ModeAuth {
		// Auth signs a fresh server nonce as a detached CMS (identity handshake).
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return CreateResponse{}, err
		}
		sess.Data = nonce
		sess.Detached = true
		sess.Format = core.FormatCMS
	} else {
		sess.Data = req.Data
		if len(sess.Data) == 0 && len(sess.Documents) == 0 {
			return CreateResponse{}, ErrNoData
		}
	}

	var appURL string
	if impl.SelfHosted() {
		appURL = trimSlash(publicBase) + appPathPrefix + id
	}
	art, err := impl.Prepare(ctx, sess, PublicURLs{DataURL: appURL, SignURL: appURL})
	if err != nil {
		return CreateResponse{}, err
	}
	qrB64, err := encodeQRBase64(art.Payload)
	if err != nil {
		return CreateResponse{}, err
	}
	if err := o.store.Create(ctx, sess); err != nil {
		return CreateResponse{}, err
	}
	return CreateResponse{
		SessionID: id, Status: string(StatusPending), QR: qrB64, Payload: art.Payload,
		EGovMobileLink: art.EGovMobileLink, EGovBusinessLink: art.EGovBusinessLink,
		DataURL: art.DataURL, SignURL: art.SignURL,
		ExpiresIn: int(ttl.Seconds()), State: req.State,
	}, nil
}

// AppData serves the data-to-sign for a self-hosted session (eGov Mobile GET).
func (o *Orchestrator) AppData(ctx context.Context, id string) (any, error) {
	sess, err := o.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !sess.ExpiresAt.After(o.now()) {
		return nil, ErrSessionExpired
	}
	impl, ok := o.profiles[sess.Profile]
	if !ok {
		return nil, ErrUnsupportedProfile
	}
	if !impl.SelfHosted() {
		return nil, ErrAppOnly
	}
	return impl.AppData(sess)
}

// SubmitSignature accepts the signature from eGov Mobile (self-hosted POST),
// verifies it and finalizes the session. It is single-use (anti-replay).
func (o *Orchestrator) SubmitSignature(ctx context.Context, id string, body []byte) error {
	sess, err := o.store.Consume(ctx, id)
	if err != nil {
		return err // ErrSessionNotFound | ErrSessionUsed
	}
	if !sess.ExpiresAt.After(o.now()) {
		return ErrSessionExpired
	}
	impl, ok := o.profiles[sess.Profile]
	if !ok {
		return ErrUnsupportedProfile
	}
	sig, err := impl.ParseAppSignature(sess, body)
	if err != nil {
		return o.fail(ctx, sess, err)
	}
	return o.complete(ctx, sess, sig)
}

// Get returns the client-safe view, lazily polling the upstream gateway for relay
// sessions and enforcing expiry.
func (o *Orchestrator) Get(ctx context.Context, id string) (View, error) {
	sess, err := o.store.Get(ctx, id)
	if err != nil {
		return View{}, err
	}
	if !sess.Status.Terminal() && !sess.ExpiresAt.After(o.now()) {
		sess.Status = StatusExpired
		_ = o.store.Save(ctx, sess)
		return sess.view(), nil
	}
	if !sess.Status.Terminal() {
		if impl, ok := o.profiles[sess.Profile]; ok && !impl.SelfHosted() {
			if updated := o.pollRelay(ctx, sess, impl); updated != nil {
				return updated.view(), nil
			}
		}
	}
	return sess.view(), nil
}

// pollRelay pulls the upstream signature once; returns the finalized session when
// it transitioned to terminal, else nil (still pending / transient error).
func (o *Orchestrator) pollRelay(ctx context.Context, sess *Session, impl Profiler) *Session {
	sig, done, err := impl.Poll(ctx, sess)
	if err != nil {
		if errors.Is(err, ErrSignatureRejected) {
			_ = o.fail(ctx, sess, err)
			s, _ := o.store.Get(ctx, sess.ID)
			return s
		}
		o.log.Debug("qr relay poll transient", "session", sess.ID, "error", err)
		return nil
	}
	if !done {
		return nil
	}
	consumed, cerr := o.store.Consume(ctx, sess.ID)
	if cerr != nil { // already consumed by a concurrent poll
		s, _ := o.store.Get(ctx, sess.ID)
		return s
	}
	_ = o.complete(ctx, consumed, sig)
	s, _ := o.store.Get(ctx, sess.ID)
	return s
}

// complete verifies the signature and stores the result / tokens.
func (o *Orchestrator) complete(ctx context.Context, sess *Session, sig []byte) error {
	res, err := o.verify(ctx, sess, sig)
	if err != nil {
		return o.fail(ctx, sess, err)
	}
	sess.Status = StatusVerified
	sess.Result = res
	if err := o.store.Save(ctx, sess); err != nil {
		return err
	}
	o.fireWebhook(ctx, sess)
	return nil
}

// verify runs the domain verification and builds the mode-specific result.
func (o *Orchestrator) verify(ctx context.Context, sess *Session, sig []byte) (json.RawMessage, error) {
	out, err := o.verifier.Verify(ctx, core.VerifyInput{
		Format:        sess.Format,
		Signature:     sig,
		Data:          sess.Data,
		Detached:      sess.Detached,
		InputPEM:      looksPEM(sig),
		CheckCertTime: true,
		ExtractClaims: true,
	})
	if err != nil {
		return nil, err
	}
	if !out.Valid || len(out.Signers) == 0 {
		return nil, ErrSignatureRejected
	}
	signer := out.Signers[0]
	if signer.Claims == nil || signer.Claims.Sub == "" {
		return nil, ErrSignatureRejected
	}
	if o.cfg.RequireOCSP {
		vr, err := o.verifier.Validate(ctx, core.ValidateInput{
			Cert: signer.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP, WantOCSP: true,
		})
		if err != nil {
			return nil, err
		}
		if vr.Status.Revoked {
			return nil, ErrCertRevoked
		}
	}
	if sess.Mode == ModeAuth {
		tok, err := o.issuer.IssueTokens(ctx, *signer.Claims, sess.ClientID, sess.ClientNonce)
		if err != nil {
			return nil, err
		}
		return json.Marshal(tok)
	}
	return json.Marshal(SignResult{Signature: sig, Valid: out.Valid, Signers: out.Signers, Claims: signer.Claims})
}

// fail marks the session failed, records the error and fires the webhook. It
// returns err so the app-facing transport reports it.
func (o *Orchestrator) fail(ctx context.Context, sess *Session, err error) error {
	sess.Status = StatusFailed
	sess.Error = explainError(err)
	_ = o.store.Save(ctx, sess)
	o.fireWebhook(ctx, sess)
	return err
}

// fireWebhook delivers the terminal view out-of-band. It detaches from the
// request context (WithoutCancel) so delivery outlives the handler, but keeps a
// bounded timeout.
func (o *Orchestrator) fireWebhook(ctx context.Context, sess *Session) {
	if o.webhook == nil || sess.CallbackURL == "" {
		return
	}
	view, url := sess.view(), sess.CallbackURL
	base := context.WithoutCancel(ctx)
	go func() {
		wctx, cancel := context.WithTimeout(base, 10*time.Second)
		defer cancel()
		o.webhook(wctx, url, view)
	}()
}

// ActiveSessions returns the stored-session count, for the metrics gauge.
func (o *Orchestrator) ActiveSessions() int { return o.store.Len() }

// Start launches the background reaper that deletes expired sessions.
func (o *Orchestrator) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(o.cfg.ReapInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := o.store.Reap(ctx, o.now()); err != nil {
					o.log.Warn("qr session reap failed", "error", err)
				} else if n > 0 {
					o.log.Debug("reaped expired qr sessions", "count", n)
				}
			}
		}
	}()
}

// Close releases the session store.
func (o *Orchestrator) Close() error { return o.store.Close() }

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// looksPEM reports whether the container is PEM-armored (vs raw DER).
func looksPEM(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN"))
}

// explainError renders an error into the client-safe BatchItemError, tagging
// soft rejections as "invalid".
func explainError(err error) *core.BatchItemError {
	kind := "internal"
	switch {
	case errors.Is(err, ErrSignatureRejected), errors.Is(err, ErrCertRevoked),
		errors.Is(err, ErrSessionExpired), errors.Is(err, ErrSessionUsed), errors.Is(err, ErrNoData):
		kind = "invalid"
	}
	return &core.BatchItemError{Kind: kind, Message: err.Error()}
}
