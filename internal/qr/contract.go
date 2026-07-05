// Package qr is the application-level QR signing/authorization orchestrator for
// eGov Mobile, built on top of the crypto primitives — not new crypto. eGov
// Mobile signs a document (or a server nonce) with the user's ЭЦП and the service
// only verifies the result server-side (the same CMS/XML that POST /verify already
// checks). This package owns the one-time TTL session around that: it hands the
// consumer a QR (as base64 PNG the consumer renders itself — no frontend here),
// hosts the public one-time URLs eGov Mobile fetches data from and returns the
// signature to, then verifies + extracts identity and either returns the signature
// or issues OIDC tokens.
//
// Three profiles decide how the QR handshake reaches eGov Mobile (selectable per
// request or by config): "agnostic" (generic one-time session, our own payload),
// "egov" (we act as the eGov QR gateway ourselves), and "relay" (we are a client
// of an existing gateway such as SIGEX). It mirrors internal/oidc (session /
// single-use consume / store) and internal/jobs (webhook delivery, client-safe
// View). Transport-independent; a REST adapter exposes it today.
package qr

import (
	"context"
	"encoding/json"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/oidc"
)

// Mode is the terminal outcome of a QR session.
type Mode string

const (
	ModeSign Mode = "sign" // return the verified signature + claims
	ModeAuth Mode = "auth" // issue OIDC tokens (login by ЭЦП via QR)
)

func (m Mode) valid() bool { return m == ModeSign || m == ModeAuth }

// Profile selects how the QR handshake reaches eGov Mobile.
type Profile string

const (
	ProfileAgnostic Profile = "agnostic" // generic: our one-time session + payload
	ProfileEGov     Profile = "egov"     // we are the eGov QR gateway ourselves
	ProfileRelay    Profile = "relay"    // we are a client of an upstream gateway (SIGEX)
)

// Status is the session lifecycle state.
type Status string

const (
	StatusPending  Status = "pending"  // awaiting the signature
	StatusVerified Status = "verified" // signature verified, result ready
	StatusFailed   Status = "failed"   // signature rejected or an error occurred
	StatusExpired  Status = "expired"  // TTL elapsed with no valid signature
)

// Terminal reports whether the session has reached a final state.
func (s Status) Terminal() bool {
	return s == StatusVerified || s == StatusFailed || s == StatusExpired
}

// Verifier is the narrow slice of the domain the flow depends on. *core.Service
// satisfies it; a fake satisfies it in tests, so the flow runs without Kalkan.
type Verifier interface {
	Verify(ctx context.Context, in core.VerifyInput) (core.VerifyOutput, error)
	Validate(ctx context.Context, in core.ValidateInput) (core.ValidateOutput, error)
}

// TokenIssuer mints OIDC tokens for auth-mode sessions through the same signer,
// JWKS and issuer as the OIDC login flow. *oidc.Provider satisfies it.
type TokenIssuer interface {
	IssueTokens(ctx context.Context, claims core.Claims, clientID, nonce string) (oidc.TokenResponse, error)
}

// Document is one item to sign, with its trilingual name and bytes (eGov profile).
type Document struct {
	NameRu string `json:"nameRu,omitempty"`
	NameKz string `json:"nameKz,omitempty"`
	NameEn string `json:"nameEn,omitempty"`
	Data   []byte `json:"data"`           // base64 on the wire
	MIME   string `json:"mime,omitempty"` // e.g. "@file/pdf"
}

// CreateRequest is the consumer's call to start a QR session.
type CreateRequest struct {
	Mode        Mode                 `json:"mode,omitempty"`       // default from config
	Profile     Profile              `json:"profile,omitempty"`    // default from config
	SignMethod  string               `json:"signMethod,omitempty"` // eGov vocab; default CMS_SIGN_ONLY
	Format      core.SignatureFormat `json:"format,omitempty"`     // cms|xml; default cms
	Detached    bool                 `json:"detached,omitempty"`
	Data        []byte               `json:"data,omitempty"` // data-to-sign (sign mode; auth mints a nonce)
	Documents   []Document           `json:"documents,omitempty"`
	Description string               `json:"description,omitempty"`
	ClientID    string               `json:"clientId,omitempty"` // auth: token audience
	State       string               `json:"state,omitempty"`
	Nonce       string               `json:"nonce,omitempty"` // auth: RP nonce echoed into id_token
	CallbackURL string               `json:"callbackUrl,omitempty"`
	TTLSeconds  int                  `json:"ttlSeconds,omitempty"`
}

// CreateResponse tells the consumer how to render the QR and where the session
// lives. QR is a base64 PNG; Payload is the raw string encoded in it (render
// either). DataURL/SignURL are the public URLs eGov Mobile uses (self-hosted
// profiles). The deep links launch the app on the same device.
type CreateResponse struct {
	SessionID        string `json:"sessionId"`
	Status           string `json:"status"`
	QR               string `json:"qr,omitempty"`      // base64-encoded PNG
	Payload          string `json:"payload,omitempty"` // raw QR content
	EGovMobileLink   string `json:"eGovMobileLink,omitempty"`
	EGovBusinessLink string `json:"eGovBusinessLink,omitempty"`
	DataURL          string `json:"dataUrl,omitempty"`
	SignURL          string `json:"signUrl,omitempty"`
	ExpiresIn        int    `json:"expiresIn"`
	State            string `json:"state,omitempty"`
}

// SignResult is the sign-mode session result: the obtained signature plus the
// verification outcome and derived claims.
type SignResult struct {
	Signature []byte        `json:"signature"`
	Valid     bool          `json:"valid"`
	Signers   []core.Signer `json:"signers,omitempty"`
	Claims    *core.Claims  `json:"claims,omitempty"`
}

// Session is the persisted record. Data may carry the document-to-sign or the
// server nonce; it and the CallbackURL never appear in the client-facing View.
type Session struct {
	ID           string               `json:"id"`
	Mode         Mode                 `json:"mode"`
	Profile      Profile              `json:"profile"`
	SignMethod   string               `json:"signMethod"`
	Format       core.SignatureFormat `json:"format"`
	Detached     bool                 `json:"detached"`
	Data         []byte               `json:"data,omitempty"`
	Documents    []Document           `json:"documents,omitempty"`
	Description  string               `json:"description,omitempty"`
	ClientID     string               `json:"clientId,omitempty"`
	ClientNonce  string               `json:"clientNonce,omitempty"`
	State        string               `json:"state,omitempty"`
	CallbackURL  string               `json:"callbackUrl,omitempty"`
	RelayID      string               `json:"relayId,omitempty"`      // relay: upstream qrId
	RelaySignURL string               `json:"relaySignUrl,omitempty"` // relay: upstream poll URL
	Status       Status               `json:"status"`
	Result       json.RawMessage      `json:"result,omitempty"`
	Error        *core.BatchItemError `json:"error,omitempty"`
	CreatedAt    time.Time            `json:"createdAt"`
	ExpiresAt    time.Time            `json:"expiresAt"`
	Used         bool                 `json:"used"` // signature submitted (single-use)
}

// View is the client-safe projection returned by status polling and pushed to a
// webhook. It omits Data, CallbackURL and relay internals.
type View struct {
	ID        string               `json:"id"`
	Mode      string               `json:"mode"`
	Profile   string               `json:"profile"`
	Status    string               `json:"status"`
	ExpiresAt time.Time            `json:"expiresAt"`
	Result    json.RawMessage      `json:"result,omitempty"`
	Error     *core.BatchItemError `json:"error,omitempty"`
}

func (s *Session) view() View {
	return View{
		ID: s.ID, Mode: string(s.Mode), Profile: string(s.Profile),
		Status: string(s.Status), ExpiresAt: s.ExpiresAt, Result: s.Result, Error: s.Error,
	}
}
