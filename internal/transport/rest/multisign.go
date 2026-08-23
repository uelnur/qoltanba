package rest

import (
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/multisign"
)

// Multi-signature sessions: POST /multisign/sessions opens a round, GET returns
// its state (who still owes a signature and the container as it stands), POST
// .../signatures accepts the container after another participant co-signed it,
// DELETE cancels the round.
//
// The service never signs here — a participant co-signs where their key is and
// submits the result.

func (s *Server) handleMultisignCreate(w http.ResponseWriter, r *http.Request) {
	var req multisign.CreateRequest
	if !decode(w, r, &req) {
		return
	}
	sess, err := s.multisign.Create(r.Context(), req)
	if err != nil {
		writeError(w, r, multisignError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sess)
}

func (s *Server) handleMultisignGet(w http.ResponseWriter, r *http.Request) {
	sess, err := s.multisign.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, multisignError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleMultisignSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Container []byte `json:"container"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Container) == 0 {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "MultisignSubmit"}, "container is required")
		return
	}
	sess, err := s.multisign.Submit(r.Context(), r.PathValue("id"), req.Container)
	if err != nil {
		writeError(w, r, multisignError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleMultisignCancel(w http.ResponseWriter, r *http.Request) {
	if err := s.multisign.Cancel(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, r, multisignError(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// multisignError maps flow errors onto the domain kinds the envelope renders.
// Every rejection here is about the caller's submission, not about the service.
func multisignError(err error) error {
	switch {
	case errors.Is(err, multisign.ErrNotFound),
		errors.Is(err, multisign.ErrSessionClosed),
		errors.Is(err, multisign.ErrNoNewSigner),
		errors.Is(err, multisign.ErrLostSigner),
		errors.Is(err, multisign.ErrNotInvited),
		errors.Is(err, multisign.ErrAlreadySigned),
		errors.Is(err, multisign.ErrInvalid):
		return &core.Error{Kind: core.KindInvalid, Op: "Multisign"}
	default:
		return &core.Error{Kind: core.KindInternal, Op: "Multisign"}
	}
}
