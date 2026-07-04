package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
)

// Job endpoints run an operation off the request path for large or slow work:
// POST /jobs returns 202 + a jobId, then the caller polls GET /jobs/{id} (status)
// and GET /jobs/{id}/result (output when finished), or supplies a callbackUrl to
// be notified. DELETE /jobs/{id} cancels. Status responses carry the job's
// client-safe view only — never the request payload (which may hold secrets).

// jobSubmit is the POST /jobs body: the operation and its payload (the same JSON
// as the corresponding sync endpoint, single or batch), plus an optional webhook.
type jobSubmit struct {
	Op          string          `json:"op"`
	Request     json.RawMessage `json:"request"`
	CallbackURL string          `json:"callbackUrl,omitempty"`
}

func (s *Server) handleJobSubmit(w http.ResponseWriter, r *http.Request) {
	var req jobSubmit
	if !decode(w, r, &req) {
		return
	}
	v, err := s.jobs.Submit(r.Context(), req.Op, req.Request, req.CallbackURL)
	if err != nil {
		writeJobError(w, err)
		return
	}
	w.Header().Set("Location", "/jobs/"+v.ID)
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Server) handleJobGet(w http.ResponseWriter, r *http.Request) {
	v, err := s.jobs.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleJobResult returns the operation output (200) once the job succeeded. A
// non-terminal job yields 409 and the current view (keep polling); a
// failed/canceled job yields 422 and the view (which carries the error).
func (s *Server) handleJobResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	raw, status, err := s.jobs.Result(r.Context(), id)
	switch {
	case errors.Is(err, jobs.ErrNotReady):
		if v, gerr := s.jobs.Get(r.Context(), id); gerr == nil {
			writeJSON(w, http.StatusConflict, v)
			return
		}
		writeJobError(w, jobs.ErrNotFound)
		return
	case err != nil:
		writeJobError(w, err)
		return
	}
	if status == jobs.StatusSucceeded {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	// Terminal but not successful: the view carries the failure/cancel reason.
	if v, gerr := s.jobs.Get(r.Context(), id); gerr == nil {
		writeJSON(w, http.StatusUnprocessableEntity, v)
		return
	}
	writeJobError(w, jobs.ErrNotFound)
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.jobs.Cancel(r.Context(), id); err != nil {
		writeJobError(w, err)
		return
	}
	v, err := s.jobs.Get(r.Context(), id)
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// writeJobError maps a job manager error to an HTTP status and the standard error
// envelope.
func writeJobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindInvalid), Message: "job not found"}})
	case errors.Is(err, jobs.ErrInvalidOp):
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "jobs"}, "unknown operation")
	case errors.Is(err, jobs.ErrTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindInvalid), Message: "request too large for an inline job"}})
	case errors.Is(err, jobs.ErrBusy):
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindUnavailable), Message: "job queue full", Action: "Retry later."}})
	default:
		writeError(w, err, "")
	}
}
