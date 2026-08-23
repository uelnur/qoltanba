// Package signedqr puts a small signed statement into a QR code, so a document
// can be checked by scanning it instead of by calling a service.
//
// This is the opposite direction from QR *signing* (internal/qr, where a phone
// signs something): here the service signs a short payload — a permit, a
// certificate of employment, a ticket — and the QR printed on the paper carries
// both the data and its signature. A verifier needs the service's public key and
// nothing else, which is what makes checking possible offline, at a checkpoint
// with no connectivity.
//
// The constraint that shapes everything here is size: a QR that must survive
// being printed small and scanned by a phone camera holds on the order of a
// kilobyte. So the payload is deliberately tiny, and the package refuses to issue
// a code that would be unreadable rather than producing one that scans badly.
package signedqr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

// Limits that keep a code scannable. maxPayloadBytes bounds the compact JWS: at
// roughly this size a QR still reads reliably from a printed page at typical
// sizes, and beyond it the code degrades into something a camera struggles with.
const (
	maxPayloadBytes = 1200
	qrPNGSize       = 512
	defaultTTL      = 365 * 24 * time.Hour
)

// docType marks the payload kind, so a verifier cannot be handed an id_token or a
// verification receipt and treat it as a document.
const docType = "qoltanba.signed-document.v1"

// Signer signs the payload — the same RS256 service key as receipts and OIDC
// tokens, published through JWKS.
type Signer interface {
	Sign(claims any) (string, error)
	KeyID() string
}

// Verifier checks a compact JWS produced by that signer.
type Verifier interface {
	Verify(token string, now time.Time) (map[string]any, error)
}

// Claims is what a signed QR carries. Data holds the document's own fields; the
// rest is what makes the statement verifiable and bounded in time.
type Claims struct {
	Type      string         `json:"typ"`
	Issuer    string         `json:"iss,omitempty"`
	Subject   string         `json:"sub,omitempty"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

// Service issues and verifies signed documents.
type Service struct {
	signer   Signer
	verifier Verifier
	issuer   string
	now      func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New builds the service over the service key.
func New(signer Signer, verifier Verifier, issuer string, opts ...Option) *Service {
	s := &Service{signer: signer, verifier: verifier, issuer: issuer, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// IssueRequest describes the document to put into a QR.
type IssueRequest struct {
	// Subject identifies who or what the statement is about (an IIN, a permit id).
	Subject string `json:"subject,omitempty"`
	// Data is the document's own fields. Keep it short — it has to fit in a code
	// someone will scan from paper.
	Data map[string]any `json:"data,omitempty"`
	// TTLSeconds bounds validity. Zero uses a year; a statement that never expires
	// cannot be withdrawn, which is rarely what an issuer wants.
	TTLSeconds int `json:"ttlSeconds,omitempty"`
	// PNGSize overrides the rendered image size in pixels.
	PNGSize int `json:"pngSize,omitempty"`
}

// IssueResponse carries both forms: the payload to embed however the caller likes,
// and a ready PNG.
type IssueResponse struct {
	Payload   string    `json:"payload"` // compact JWS — this is what the QR encodes
	QR        string    `json:"qr"`      // base64 PNG
	Bytes     int       `json:"bytes"`   // payload size, for callers tuning their data
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Issue signs the document and renders its QR.
func (s *Service) Issue(req IssueRequest) (IssueResponse, error) {
	if s.signer == nil {
		return IssueResponse{}, fmt.Errorf("signedqr: no service signing key configured")
	}
	now := s.now()
	ttl := defaultTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	expires := now.Add(ttl)

	token, err := s.signer.Sign(Claims{
		Type: docType, Issuer: s.issuer, Subject: req.Subject,
		IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), Data: req.Data,
	})
	if err != nil {
		return IssueResponse{}, fmt.Errorf("signedqr: sign: %w", err)
	}
	if len(token) > maxPayloadBytes {
		// Refusing beats emitting a code that scans badly in the field: the caller
		// can still shorten the data, but they cannot fix a printed permit.
		return IssueResponse{}, fmt.Errorf(
			"signedqr: payload is %d bytes, over the %d-byte limit for a reliably scannable code — carry fewer fields, or reference them by id",
			len(token), maxPayloadBytes)
	}

	size := req.PNGSize
	if size <= 0 {
		size = qrPNGSize
	}
	// Medium correction: enough redundancy for a printed page that gets folded or
	// smudged, without inflating the code as High would.
	png, err := qrcode.Encode(token, qrcode.Medium, size)
	if err != nil {
		return IssueResponse{}, fmt.Errorf("signedqr: render: %w", err)
	}

	return IssueResponse{
		Payload: token, QR: base64.StdEncoding.EncodeToString(png), Bytes: len(token),
		IssuedAt: now.UTC(), ExpiresAt: expires.UTC(),
	}, nil
}

// VerifyResult is the outcome of checking a scanned payload.
type VerifyResult struct {
	Valid     bool           `json:"valid"`
	Reason    string         `json:"reason,omitempty"`
	Issuer    string         `json:"issuer,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	IssuedAt  *time.Time     `json:"issuedAt,omitempty"`
	ExpiresAt *time.Time     `json:"expiresAt,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

// Verify checks a scanned payload against the service key. A payload that does
// not verify is a result, not an error: "this permit is forged" is exactly what
// the caller asked to find out.
func (s *Service) Verify(payload string) VerifyResult {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return VerifyResult{Reason: "empty payload"}
	}
	if s.verifier == nil {
		return VerifyResult{Reason: "no service key configured to verify against"}
	}
	claims, err := s.verifier.Verify(payload, s.now())
	if err != nil {
		return VerifyResult{Reason: err.Error()}
	}
	if typ, _ := claims["typ"].(string); typ != docType {
		// Without this a receipt or an id_token — both signed by the same key —
		// would pass as a document.
		return VerifyResult{Reason: "payload is not a signed document"}
	}

	res := VerifyResult{Valid: true}
	res.Issuer, _ = claims["iss"].(string)
	res.Subject, _ = claims["sub"].(string)
	if iat, ok := numericTime(claims["iat"]); ok {
		res.IssuedAt = &iat
	}
	if exp, ok := numericTime(claims["exp"]); ok {
		res.ExpiresAt = &exp
	}
	if data, ok := claims["data"].(map[string]any); ok {
		res.Data = data
	}
	return res
}

// numericTime reads a JWT numeric date, which JSON decoding gives us as float64.
func numericTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0).UTC(), true
	case int64:
		return time.Unix(n, 0).UTC(), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}
