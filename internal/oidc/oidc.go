package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Config tunes the OIDC flow. Zero values fall back to safe defaults.
type Config struct {
	// Issuer is the OIDC issuer identifier and the base URL for discovery links
	// (iss claim, jwks_uri, endpoints). Required.
	Issuer string
	// Audience is the default id_token aud when a verify request omits clientId.
	Audience     string
	ChallengeTTL time.Duration // how long an issued challenge is valid (default 5m)
	TokenTTL     time.Duration // id_token/access_token lifetime (default 1h)
	RequireOCSP  bool          // require a good OCSP status before issuing tokens
	ReapInterval time.Duration // expired-challenge sweep cadence (default min(ChallengeTTL, 1m))
}

func (c Config) withDefaults() Config {
	if c.ChallengeTTL <= 0 {
		c.ChallengeTTL = 5 * time.Minute
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = time.Hour
	}
	if c.ReapInterval <= 0 {
		c.ReapInterval = c.ChallengeTTL
		if c.ReapInterval > time.Minute {
			c.ReapInterval = time.Minute
		}
	}
	return c
}

// Provider runs the challenge/verify flow and issues tokens. It owns no crypto of
// its own beyond the RS256 token signer — signature verification and revocation
// are delegated to the domain — so it is tested without Kalkan.
type Provider struct {
	verifier Verifier
	signer   *Signer
	store    ChallengeStore
	cfg      Config
	log      *slog.Logger
	now      func() time.Time
}

// Option configures a Provider.
type Option func(*Provider)

// WithLogger sets the structured logger (nil-safe: the default logger is used).
func WithLogger(l *slog.Logger) Option {
	return func(p *Provider) {
		if l != nil {
			p.log = l
		}
	}
}

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// New builds a Provider over the domain verifier, RS256 signer and challenge
// store.
func New(v Verifier, signer *Signer, store ChallengeStore, cfg Config, opts ...Option) *Provider {
	p := &Provider{
		verifier: v,
		signer:   signer,
		store:    store,
		cfg:      cfg.withDefaults(),
		log:      slog.Default(),
		now:      time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Challenge issues a fresh nonce for the client to sign as a detached CMS.
func (p *Provider) Challenge(ctx context.Context, req ChallengeRequest) (ChallengeResponse, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ChallengeResponse{}, err
	}
	id, err := randID()
	if err != nil {
		return ChallengeResponse{}, err
	}
	now := p.now()
	ch := &Challenge{
		ID:          id,
		Nonce:       nonce,
		ClientNonce: req.Nonce,
		State:       req.State,
		CreatedAt:   now,
		ExpiresAt:   now.Add(p.cfg.ChallengeTTL),
	}
	if err := p.store.Create(ctx, ch); err != nil {
		return ChallengeResponse{}, err
	}
	return ChallengeResponse{
		ChallengeID: id,
		Data:        stdB64(nonce),
		Alg:         "CMS-detached",
		ExpiresIn:   int(p.cfg.ChallengeTTL.Seconds()),
		State:       req.State,
	}, nil
}

// Verify consumes the challenge, verifies the user's detached CMS over the nonce
// (optionally checking revocation), and mints the OIDC token set from the
// signer's certificate-derived claims.
func (p *Provider) Verify(ctx context.Context, req VerifyRequest) (TokenResponse, error) {
	ch, err := p.store.Consume(ctx, req.ChallengeID)
	if err != nil {
		return TokenResponse{}, err // ErrChallengeNotFound | ErrChallengeUsed
	}
	if !ch.ExpiresAt.After(p.now()) {
		return TokenResponse{}, ErrChallengeExpired
	}
	if len(req.Signature) == 0 {
		return TokenResponse{}, ErrSignatureRejected
	}

	out, err := p.verifier.Verify(ctx, core.VerifyInput{
		Format:        core.FormatCMS,
		Signature:     req.Signature,
		Data:          ch.Nonce,
		Detached:      true,
		InputPEM:      looksPEM(req.Signature),
		CheckCertTime: true,
		ExtractClaims: true,
	})
	if err != nil {
		return TokenResponse{}, err // hard driver/domain failure → server_error
	}
	if !out.Valid || len(out.Signers) == 0 {
		return TokenResponse{}, ErrSignatureRejected
	}
	signer := out.Signers[0]
	if signer.Claims == nil || signer.Claims.Sub == "" {
		return TokenResponse{}, ErrSignatureRejected
	}

	if p.cfg.RequireOCSP {
		res, err := p.verifier.Validate(ctx, core.ValidateInput{
			Cert:     signer.Certificate.PEM,
			Format:   core.EncodingPEM,
			Method:   core.MethodOCSP,
			WantOCSP: true,
		})
		if err != nil {
			return TokenResponse{}, err
		}
		if res.Status.Revoked {
			return TokenResponse{}, ErrCertRevoked
		}
	}

	now := p.now()
	sub := signer.Claims.Sub
	aud := firstNonEmpty(req.ClientID, p.cfg.Audience, p.cfg.Issuer)

	idClaims := claimsToMap(*signer.Claims)
	idClaims["iss"] = p.cfg.Issuer
	idClaims["sub"] = sub
	idClaims["aud"] = aud
	idClaims["iat"] = now.Unix()
	idClaims["auth_time"] = now.Unix()
	idClaims["exp"] = now.Add(p.cfg.TokenTTL).Unix()
	if ch.ClientNonce != "" {
		idClaims["nonce"] = ch.ClientNonce
	}

	accClaims := claimsToMap(*signer.Claims)
	accClaims["iss"] = p.cfg.Issuer
	accClaims["sub"] = sub
	accClaims["iat"] = now.Unix()
	accClaims["exp"] = now.Add(p.cfg.TokenTTL).Unix()
	accClaims["token_use"] = "access"

	idToken, err := p.signer.Sign(idClaims)
	if err != nil {
		return TokenResponse{}, err
	}
	accessToken, err := p.signer.Sign(accClaims)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		IDToken:     idToken,
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(p.cfg.TokenTTL.Seconds()),
	}, nil
}

// UserInfo validates a bearer access token and returns its claims.
func (p *Provider) UserInfo(_ context.Context, bearer string) (map[string]any, error) {
	return p.signer.Verify(strings.TrimSpace(bearer), p.now())
}

// Discovery returns the OpenID Connect discovery document for this provider.
func (p *Provider) Discovery() DiscoveryDoc {
	base := strings.TrimRight(p.cfg.Issuer, "/")
	return DiscoveryDoc{
		Issuer:                           p.cfg.Issuer,
		JWKSURI:                          base + "/oidc/jwks.json",
		TokenEndpoint:                    base + "/oidc/verify",
		UserinfoEndpoint:                 base + "/oidc/userinfo",
		ChallengeEndpoint:                base + "/oidc/challenge",
		GrantTypesSupported:              []string{"urn:qoltanba:params:grant-type:ecp"},
		ResponseTypesSupported:           []string{"id_token", "token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile"},
		ClaimsSupported: []string{
			"sub", "name", "given_name", "family_name", "email",
			"iin", "bin", "organization", "roles", "owner_type", "gender",
		},
	}
}

// JWKS returns the public key set for token verification.
func (p *Provider) JWKS() JWKSet { return p.signer.JWKS() }

// Signer exposes the token signer (used by main to log key-source facts).
func (p *Provider) Signer() *Signer { return p.signer }

// ActiveChallenges returns the current stored-challenge count, for the metrics
// gauge.
func (p *Provider) ActiveChallenges() int { return p.store.Len() }

// Start launches the background reaper that deletes expired challenges. It
// returns when ctx is canceled.
func (p *Provider) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(p.cfg.ReapInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := p.store.Reap(ctx, p.now()); err != nil {
					p.log.Warn("oidc challenge reap failed", "error", err)
				} else if n > 0 {
					p.log.Debug("reaped expired challenges", "count", n)
				}
			}
		}
	}()
}

// Close releases the challenge store.
func (p *Provider) Close() error { return p.store.Close() }

// stdB64 renders the nonce as standard base64 for the wire; the client decodes it
// to the raw bytes it must sign (which is what the server keeps and verifies).
func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// randID returns a URL-safe random identifier for a challenge.
func randID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// looksPEM reports whether the CMS container is PEM-armored (as opposed to raw
// DER), so the domain sets the right input flag.
func looksPEM(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN"))
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
