package qr

import (
	"context"
	"encoding/json"
)

// agnosticProfile is the protocol-agnostic self-hosted profile: the QR encodes our
// one-time public data URL, a generic client (or the consumer's own integration)
// fetches the data-to-sign there and posts back the signature. No eGov-specific
// framing — useful when the consumer's client defines the exact handshake.
type agnosticProfile struct{}

// NewAgnosticProfile builds the protocol-agnostic self-hosted profile.
func NewAgnosticProfile() Profiler { return agnosticProfile{} }

func (agnosticProfile) SelfHosted() bool { return true }

func (agnosticProfile) Prepare(_ context.Context, _ *Session, urls PublicURLs) (Artifacts, error) {
	// The QR carries the public data URL directly; the unguessable session id in the
	// path is the capability token.
	return Artifacts{Payload: urls.DataURL, DataURL: urls.DataURL, SignURL: urls.SignURL}, nil
}

func (agnosticProfile) AppData(s *Session) (any, error) {
	return map[string]any{
		"id":          s.ID,
		"data":        s.Data, // base64 on the wire
		"format":      string(s.Format),
		"detached":    s.Detached,
		"description": s.Description,
	}, nil
}

func (agnosticProfile) ParseAppSignature(_ *Session, body []byte) ([]byte, error) {
	var in struct {
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	if len(in.Signature) == 0 {
		return nil, ErrSignatureRejected
	}
	return in.Signature, nil
}

func (agnosticProfile) Poll(context.Context, *Session) ([]byte, bool, error) {
	return nil, false, ErrAppOnly
}
