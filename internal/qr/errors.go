package qr

import "errors"

// Flow errors. The REST adapter maps these to HTTP statuses; a bare domain error
// from the Verifier passes through as a server fault.
var (
	ErrSessionNotFound    = errors.New("qr: session not found")
	ErrSessionUsed        = errors.New("qr: session signature already submitted")
	ErrSessionExpired     = errors.New("qr: session expired")
	ErrSignatureRejected  = errors.New("qr: signature invalid or no signer")
	ErrCertRevoked        = errors.New("qr: signer certificate revoked")
	ErrUnsupportedProfile = errors.New("qr: unsupported profile")
	ErrUnsupportedMode    = errors.New("qr: unsupported mode")
	ErrAuthUnavailable    = errors.New("qr: auth mode requires the OIDC token issuer")
	ErrNoData             = errors.New("qr: no data to sign")
	ErrAppOnly            = errors.New("qr: endpoint not served for this profile")
)
