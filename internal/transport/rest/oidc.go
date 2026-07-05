package rest

import (
	"errors"
	"net/http"
	"strings"

	"github.com/uelnur/qoltanba/internal/oidc"
)

// OIDC endpoints implement a "login with ЭЦП" flow: GET
// /.well-known/openid-configuration and /oidc/jwks.json let a relying party
// discover and verify tokens; POST /oidc/challenge issues a nonce; POST
// /oidc/verify takes the user's detached CMS over that nonce and returns an
// id_token/access_token; GET /oidc/userinfo returns claims for a bearer token.
// Errors follow the OAuth2 {error, error_description} shape relying parties
// expect, not the service's generic envelope.

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.oidc.Discovery())
}

func (s *Server) handleOIDCJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.oidc.JWKS())
}

func (s *Server) handleOIDCChallenge(w http.ResponseWriter, r *http.Request) {
	var req oidc.ChallengeRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.oidc.Challenge(r.Context(), req)
	if err != nil {
		writeOIDCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleOIDCVerify(w http.ResponseWriter, r *http.Request) {
	var req oidc.VerifyRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.oidc.Verify(r.Context(), req)
	if err != nil {
		writeOIDCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimSpace(r.Header.Get("Authorization"))
	if after, ok := strings.CutPrefix(bearer, "Bearer "); ok {
		bearer = after
	}
	if bearer == "" {
		writeOIDCError(w, oidc.ErrTokenInvalid)
		return
	}
	claims, err := s.oidc.UserInfo(r.Context(), bearer)
	if err != nil {
		writeOIDCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// oauthError is the OAuth2/OIDC error envelope.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// writeOIDCError maps a flow error to an OAuth2 error response and HTTP status.
// Unknown errors surface as a 500 server_error without leaking internals.
func writeOIDCError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oidc.ErrChallengeNotFound):
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "challenge not found"})
	case errors.Is(err, oidc.ErrChallengeExpired):
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "challenge expired"})
	case errors.Is(err, oidc.ErrChallengeUsed):
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "challenge already used"})
	case errors.Is(err, oidc.ErrSignatureRejected):
		writeJSON(w, http.StatusUnauthorized, oauthError{"access_denied", "signature rejected"})
	case errors.Is(err, oidc.ErrCertRevoked):
		writeJSON(w, http.StatusUnauthorized, oauthError{"access_denied", "certificate revoked"})
	case errors.Is(err, oidc.ErrTokenInvalid):
		writeJSON(w, http.StatusUnauthorized, oauthError{"invalid_token", "token invalid"})
	case errors.Is(err, oidc.ErrTokenExpired):
		writeJSON(w, http.StatusUnauthorized, oauthError{"invalid_token", "token expired"})
	default:
		writeJSON(w, http.StatusInternalServerError, oauthError{"server_error", ""})
	}
}
