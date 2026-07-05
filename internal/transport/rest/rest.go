// Package rest is the HTTP/JSON transport: a thin adapter that decodes a request
// into a core input, calls the domain service, and encodes the output. It holds
// no crypto or driver logic. One http.Server serves it over TCP or a Unix
// socket; wiring lives in main.
package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/transport/dto"
)

// Server adapts the domain service to HTTP handlers.
type Server struct {
	svc  *core.Service
	jobs *jobs.Manager  // nil disables the async-job endpoints
	oidc *oidc.Provider // nil disables the OIDC endpoints
}

// Option configures a Server.
type Option func(*Server)

// WithJobs enables the async-job endpoints backed by the given manager.
func WithJobs(m *jobs.Manager) Option { return func(s *Server) { s.jobs = m } }

// WithOIDC enables the "login with ЭЦП" OIDC endpoints backed by the given provider.
func WithOIDC(p *oidc.Provider) Option { return func(s *Server) { s.oidc = p } }

// New builds a REST server over the domain service.
func New(svc *core.Service, opts ...Option) *Server {
	s := &Server{svc: svc}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Routes returns the work-endpoint handler (sign/verify/extract/cert).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sign", s.handleSign)
	mux.HandleFunc("POST /sign/add", s.handleSign) // co-sign via ExistingSignature
	mux.HandleFunc("POST /verify", s.handleVerify)
	mux.HandleFunc("POST /extract", s.handleExtract)
	mux.HandleFunc("POST /cert/info", s.handleCertInfo)
	mux.HandleFunc("POST /cert/validate", s.handleValidate)
	mux.HandleFunc("POST /sign/batch", s.handleSignBatch)
	mux.HandleFunc("POST /verify/batch", s.handleVerifyBatch)
	mux.HandleFunc("POST /extract/batch", s.handleExtractBatch)
	mux.HandleFunc("POST /cert/info/batch", s.handleCertInfoBatch)
	mux.HandleFunc("POST /cert/validate/batch", s.handleValidateBatch)
	if s.jobs != nil {
		mux.HandleFunc("POST /jobs", s.handleJobSubmit)
		mux.HandleFunc("GET /jobs/{id}", s.handleJobGet)
		mux.HandleFunc("GET /jobs/{id}/result", s.handleJobResult)
		mux.HandleFunc("DELETE /jobs/{id}", s.handleJobCancel)
	}
	if s.oidc != nil {
		mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCDiscovery)
		mux.HandleFunc("GET /oidc/jwks.json", s.handleOIDCJWKS)
		mux.HandleFunc("POST /oidc/challenge", s.handleOIDCChallenge)
		mux.HandleFunc("POST /oidc/verify", s.handleOIDCVerify)
		mux.HandleFunc("GET /oidc/userinfo", s.handleOIDCUserInfo)
	}
	return mux
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req dto.SignRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := req.ToCore()
	if err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "Sign"}, err.Error())
		return
	}
	out, err := s.svc.Sign(r.Context(), in)
	if err != nil {
		writeError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := req.ToCore()
	if err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "Verify"}, err.Error())
		return
	}
	out, err := s.svc.Verify(r.Context(), in)
	if err != nil {
		writeError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleExtract(w http.ResponseWriter, r *http.Request) {
	var req dto.ExtractRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := req.ToCore()
	if err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "Extract"}, err.Error())
		return
	}
	out, err := s.svc.Extract(r.Context(), in)
	if err != nil {
		writeError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCertInfo(w http.ResponseWriter, r *http.Request) {
	var req dto.CertInfoRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.svc.CertInfo(r.Context(), req.ToCore())
	if err != nil {
		writeError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req dto.ValidateRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.svc.Validate(r.Context(), req.ToCore())
	if err != nil {
		writeError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// decode reads a JSON body, writing a 400 on failure. It reports success.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "decode"}, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// maxBodyBytes caps inline request size; large data goes by reference (future).
const maxBodyBytes = 32 << 20 // 32 MiB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody is the JSON error envelope for hard failures.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Kind    string `json:"kind"`
	Code    string `json:"code,omitempty"`   // raw KCR_* code when present
	Message string `json:"message"`          // friendly, from the error catalog
	Action  string `json:"action,omitempty"` // suggested remedy
}

// writeError maps a domain error to an HTTP status and JSON envelope, rendering a
// friendly message/action from the error catalog. msg overrides the message when
// non-empty (used for pre-service request validation, which has no catalog entry).
func writeError(w http.ResponseWriter, err error, msg string) {
	kind := core.KindInternal
	var de *core.Error
	if errors.As(err, &de) {
		kind = de.Kind
	}
	exp := core.Explain(err)
	if msg == "" {
		msg = exp.Message
	}
	if msg == "" && err != nil {
		msg = err.Error()
	}
	writeJSON(w, statusFor(kind), errorBody{Error: errorDetail{
		Kind: core.KindName(kind), Code: exp.Code, Message: msg, Action: exp.Action,
	}})
}

func statusFor(k core.ErrorKind) int {
	switch k {
	case core.KindInvalid:
		return http.StatusBadRequest
	case core.KindUnsupported:
		return http.StatusNotImplemented
	case core.KindUnavailable:
		return http.StatusServiceUnavailable
	case core.KindCanceled:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}
