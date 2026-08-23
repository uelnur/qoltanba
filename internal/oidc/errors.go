package oidc

import (
	"errors"

	"github.com/uelnur/qoltanba/internal/challenge"
)

// Flow errors. The REST adapter maps each to an OAuth2/OIDC error response
// ({error, error_description}); anything else surfaces as a generic server_error.
var (
	// ErrChallengeNotFound means the challengeId is unknown (never issued, or
	// already reaped after expiry).
	ErrChallengeNotFound = challenge.ErrNotFound
	// ErrChallengeExpired means the challenge outlived its TTL.
	ErrChallengeExpired = challenge.ErrExpired
	// ErrChallengeUsed means the challenge was already consumed (anti-replay).
	ErrChallengeUsed = challenge.ErrUsed
	// ErrSignatureRejected means the CMS signature did not verify, carried no
	// signer, or lacked an extractable subject identity.
	ErrSignatureRejected = errors.New("signature rejected")
	// ErrCertRevoked means the signer certificate is revoked per OCSP/CRL.
	ErrCertRevoked = errors.New("certificate revoked")
	// ErrTokenInvalid means an access token failed signature or structural checks.
	ErrTokenInvalid = errors.New("token invalid")
	// ErrTokenExpired means an access token is past its exp.
	ErrTokenExpired = errors.New("token expired")
)
