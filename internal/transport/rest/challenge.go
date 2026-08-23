package rest

import (
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/challenge"
	"github.com/uelnur/qoltanba/internal/core"
)

// Challenge endpoints expose the anti-replay handshake as a standalone primitive:
// POST /challenge issues a single-use nonce bound to a purpose, POST
// /challenge/confirm takes the user's detached CMS over that nonce and reports who
// signed it. The same flow inside /oidc/* mints login tokens; here the caller
// decides what the confirmation authorizes (a payment, an approval, a consent).

func (s *Server) handleChallengeIssue(w http.ResponseWriter, r *http.Request) {
	var req challenge.IssueRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.challenge.Issue(r.Context(), req)
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInternal, Op: "Challenge"}, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleChallengeConfirm(w http.ResponseWriter, r *http.Request) {
	var req challenge.ConfirmRequest
	if !decode(w, r, &req) {
		return
	}
	if req.ChallengeID == "" || len(req.Signature) == 0 {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "ChallengeConfirm"},
			"challengeId and signature are required")
		return
	}
	out, err := s.challenge.Confirm(r.Context(), req)
	if err != nil {
		writeError(w, r, challengeError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// challengeError maps the challenge lifecycle errors onto the domain error kinds
// the envelope understands: an unknown, stale or replayed id is the caller's
// problem, anything else is ours.
func challengeError(err error) error {
	switch {
	case errors.Is(err, challenge.ErrNotFound),
		errors.Is(err, challenge.ErrExpired),
		errors.Is(err, challenge.ErrUsed):
		return &core.Error{Kind: core.KindInvalid, Op: "ChallengeConfirm"}
	default:
		return &core.Error{Kind: core.KindInternal, Op: "ChallengeConfirm"}
	}
}
