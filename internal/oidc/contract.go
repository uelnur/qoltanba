// Package oidc is the application-level "login with ЭЦП" flow built on top of the
// crypto primitives: a challenge/verify handshake that turns a user's detached
// CMS signature over a server nonce into standard OpenID Connect tokens.
//
// It is transport-independent (a REST adapter exposes it today; gRPC could later)
// and mirrors the structure of internal/jobs: a small service orchestrating the
// domain (core.Service) plus a non-crypto concern — minting the service's own
// JWTs. The user signs the nonce with a GOST key via Kalkan (which the domain
// verifies); the id_token/access_token we hand a relying party are signed with a
// local RS256 key published through JWKS, so any off-the-shelf OIDC client can
// verify them. The private signing key never leaves the service; the user's key
// never leaves their device (NCALayer/eGov). The browser step is driven by the
// consuming application — this package hosts no login page (see roadmap non-goal
// on UI/frontend signing).
package oidc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Verifier is the narrow slice of the domain the flow depends on: verify a
// signature and check certificate revocation. *core.Service satisfies it, and a
// fake satisfies it in tests, so the flow is exercised without Kalkan.
type Verifier interface {
	Verify(ctx context.Context, in core.VerifyInput) (core.VerifyOutput, error)
	Validate(ctx context.Context, in core.ValidateInput) (core.ValidateOutput, error)
}

// ChallengeRequest optionally carries a relying-party nonce and state to echo
// back: nonce is bound into the id_token (OIDC replay protection for the RP),
// state is returned verbatim for the caller to correlate.
type ChallengeRequest struct {
	Nonce string `json:"nonce,omitempty"`
	State string `json:"state,omitempty"`
}

// ChallengeResponse tells the client what to sign. Data is the base64 nonce the
// user must sign as a detached CMS; ChallengeID ties the later verify call back
// to this challenge. ExpiresIn is seconds until the challenge is no longer valid.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Data        string `json:"data"` // base64 nonce to sign (detached CMS)
	Alg         string `json:"alg"`  // signing form expected: "CMS-detached"
	ExpiresIn   int    `json:"expiresIn"`
	State       string `json:"state,omitempty"`
}

// VerifyRequest submits the user's detached CMS signature over the challenge
// nonce. Signature is the CMS container (PEM or DER; base64 on the wire).
// ClientID, when set, becomes the id_token audience.
type VerifyRequest struct {
	ChallengeID string `json:"challengeId"`
	Signature   []byte `json:"signature"`
	ClientID    string `json:"clientId,omitempty"`
}

// TokenResponse is the OIDC token set issued on a successful verify.
type TokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// DiscoveryDoc is the subset of the OpenID Connect discovery document this
// provider advertises. There is no authorization_endpoint: the flow is a custom
// grant (challenge/verify) driven by the consuming app, not a browser redirect.
type DiscoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	ChallengeEndpoint                string   `json:"challenge_endpoint"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// JWK is a public RSA key in JWK form.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // base64url modulus
	E   string `json:"e"` // base64url exponent
}

// JWKSet is the JSON Web Key Set published at jwks_uri.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Challenge is one issued nonce awaiting a signature. It is single-use
// (anti-replay) and expires after the configured TTL.
type Challenge struct {
	ID          string    `json:"id"`
	Nonce       []byte    `json:"nonce"`
	ClientNonce string    `json:"clientNonce,omitempty"`
	State       string    `json:"state,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Used        bool      `json:"used"`
}

// claimsToMap flattens the certificate-derived OIDC claims into a mutable map so
// standard claims (iss/aud/iat/exp/…) can be layered on top before signing.
func claimsToMap(c core.Claims) map[string]any {
	b, err := json.Marshal(c)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}
