// Package rest is the HTTP/JSON transport: a thin adapter that decodes a request
// into a core input, calls the domain service, and encodes the output. It holds
// no crypto or driver logic. One http.Server serves it over TCP or a Unix
// socket; wiring lives in main.
package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/audit"
	"github.com/uelnur/qoltanba/internal/challenge"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/idempotency"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/multisign"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/qr"
	"github.com/uelnur/qoltanba/internal/signedqr"
	"github.com/uelnur/qoltanba/internal/transport/dto"
)

// Server adapts the domain service to HTTP handlers.
type Server struct {
	svc  *core.Service
	jobs *jobs.Manager    // nil disables the async-job endpoints
	oidc *oidc.Provider   // nil disables the OIDC endpoints
	qr   *qr.Orchestrator // nil disables the QR endpoints
	// challenge serves the standalone challenge-response endpoints; nil disables them.
	challenge *challenge.Service
	// multisign serves the multi-signature session endpoints; nil disables them.
	multisign *multisign.Service
	// auditPath and auditVerifier expose the tamper-evident journal; an empty path
	// disables the endpoints.
	auditPath     string
	auditVerifier func(audit.Entry) error
	// console serves the try-it page; sandboxKey/sandboxPass enable demo signing.
	console     bool
	sandboxKey  string
	sandboxPass string
	// signedQR issues and checks QR-carried signed documents; nil disables them.
	signedQR *signedqr.Service
	// portal serves the human verification page. Off by default: it accepts
	// uploads from anyone who can reach it.
	portal bool
	idem   *idempotency.Cache // nil disables Idempotency-Key handling
	qrBase string             // configured public base URL for QR app-facing links
	// jwks publishes the service's public signing key. It is set by OIDC or by
	// receipts: whoever verifies a service-signed statement needs the key, and
	// receipts work with OIDC disabled.
	jwks func() oidc.JWKSet
}

// Option configures a Server.
type Option func(*Server)

// WithJobs enables the async-job endpoints backed by the given manager.
func WithJobs(m *jobs.Manager) Option { return func(s *Server) { s.jobs = m } }

// WithOIDC enables the "login with ЭЦП" OIDC endpoints backed by the given provider.
func WithOIDC(p *oidc.Provider) Option {
	return func(s *Server) { s.oidc = p; s.jwks = p.JWKS }
}

// WithServiceKey publishes the service signing key at /jwks.json so a consumer can
// verify signed verification receipts. OIDC sets the same publisher; this option
// covers the receipts-without-OIDC case.
func WithServiceKey(signer *oidc.Signer) Option {
	return func(s *Server) {
		if s.jwks == nil {
			s.jwks = signer.JWKS
		}
	}
}

// WithMultisign enables the multi-signature session endpoints.
func WithMultisign(m *multisign.Service) Option { return func(s *Server) { s.multisign = m } }

// WithAudit exposes the tamper-evident journal at /audit/*. verifier checks each
// entry's signature; nil checks the hash chain only, which catches edits but not
// a chain re-sealed by someone holding the service key.
func WithAudit(path string, verifier func(audit.Entry) error) Option {
	return func(s *Server) { s.auditPath, s.auditVerifier = path, verifier }
}

// WithConsole enables the try-it console at /console.
func WithConsole() Option { return func(s *Server) { s.console = true } }

// WithSandboxKey enables demo signing at /sandbox/sign with the given key. Only
// ever point it at a test container: anyone who can reach the endpoint can sign
// arbitrary bytes with it.
func WithSandboxKey(path, password string) Option {
	return func(s *Server) { s.sandboxKey, s.sandboxPass = path, password }
}

// WithSignedQR enables QR-carried signed documents at /qr/documents.
func WithSignedQR(svc *signedqr.Service) Option { return func(s *Server) { s.signedQR = svc } }

// WithPortal enables the human verification page at /verify/portal.
func WithPortal() Option { return func(s *Server) { s.portal = true } }

// WithChallenge enables the standalone challenge-response endpoints.
func WithChallenge(c *challenge.Service) Option { return func(s *Server) { s.challenge = c } }

// WithQR enables the eGov Mobile QR signing/auth endpoints. publicBase is the
// externally reachable base URL used to build the app-facing links embedded in the
// QR (empty falls back to X-Forwarded-*/Host per request).
func WithQR(o *qr.Orchestrator, publicBase string) Option {
	return func(s *Server) { s.qr = o; s.qrBase = publicBase }
}

// New builds a REST server over the domain service.
func New(svc *core.Service, opts ...Option) *Server {
	s := &Server{svc: svc}
	for _, o := range opts {
		o(s)
	}
	return s
}

// withLocale puts the request's preferred language into the context, so error
// messages come back in it. Accept-Language is the standard signal; an absent or
// unsupported value renders English.
func withLocale(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag := r.Header.Get("Accept-Language"); tag != "" {
			r = r.WithContext(core.ContextWithLocale(r.Context(), tag))
		}
		next.ServeHTTP(w, r)
	})
}

// Routes returns the work-endpoint handler (sign/verify/extract/cert).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	// Mutating/expensive ops honor Idempotency-Key (replay a prior response on a
	// retry). Read-only status endpoints do not need it.
	mux.HandleFunc("POST /sign", s.idempotent(s.handleSign))
	mux.HandleFunc("POST /sign/add", s.idempotent(s.handleSign)) // co-sign via ExistingSignature
	mux.HandleFunc("POST /verify", s.idempotent(s.handleVerify))
	mux.HandleFunc("POST /verify/at", s.idempotent(s.handleVerifyAt))
	mux.HandleFunc("POST /extract", s.idempotent(s.handleExtract))
	mux.HandleFunc("POST /cert/info", s.idempotent(s.handleCertInfo))
	mux.HandleFunc("POST /cert/validate", s.idempotent(s.handleValidate))
	mux.HandleFunc("POST /sign/batch", s.idempotent(s.handleSignBatch))
	mux.HandleFunc("POST /verify/batch", s.idempotent(s.handleVerifyBatch))
	mux.HandleFunc("POST /verify/registry", s.idempotent(s.handleVerifyRegistry))
	mux.HandleFunc("POST /sign/archive", s.idempotent(s.handleArchive))
	mux.HandleFunc("POST /extract/batch", s.idempotent(s.handleExtractBatch))
	mux.HandleFunc("POST /cert/info/batch", s.idempotent(s.handleCertInfoBatch))
	mux.HandleFunc("POST /cert/validate/batch", s.idempotent(s.handleValidateBatch))
	if s.jobs != nil {
		mux.HandleFunc("POST /jobs", s.handleJobSubmit)
		mux.HandleFunc("GET /jobs/{id}", s.handleJobGet)
		mux.HandleFunc("GET /jobs/{id}/result", s.handleJobResult)
		mux.HandleFunc("DELETE /jobs/{id}", s.handleJobCancel)
	}
	if s.jwks != nil {
		mux.HandleFunc("GET /jwks.json", s.handleJWKS)
	}
	if s.oidc != nil {
		mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCDiscovery)
		mux.HandleFunc("GET /oidc/jwks.json", s.handleOIDCJWKS)
		mux.HandleFunc("POST /oidc/challenge", s.handleOIDCChallenge)
		mux.HandleFunc("POST /oidc/verify", s.handleOIDCVerify)
		mux.HandleFunc("GET /oidc/authorize", s.handleOIDCAuthorize)
		mux.HandleFunc("POST /oidc/authorize", s.handleOIDCAuthorizeSubmit)
		mux.HandleFunc("POST /oidc/token", s.handleOIDCToken)
		mux.HandleFunc("GET /oidc/userinfo", s.handleOIDCUserInfo)
	}
	if s.signedQR != nil {
		mux.HandleFunc("POST /qr/documents", s.handleSignedQRIssue)
		mux.HandleFunc("POST /qr/documents/verify", s.handleSignedQRVerify)
	}
	if s.console {
		mux.HandleFunc("GET /console", s.handleConsole)
	}
	if s.sandboxKey != "" {
		mux.HandleFunc("POST /sandbox/sign", s.handleSandboxSign)
	}
	if s.auditPath != "" {
		mux.HandleFunc("GET /audit/verify", s.handleAuditVerify)
		mux.HandleFunc("GET /audit/export", s.handleAuditExport)
	}
	if s.multisign != nil {
		mux.HandleFunc("POST /multisign/sessions", s.handleMultisignCreate)
		mux.HandleFunc("GET /multisign/sessions/{id}", s.handleMultisignGet)
		mux.HandleFunc("POST /multisign/sessions/{id}/signatures", s.handleMultisignSubmit)
		mux.HandleFunc("DELETE /multisign/sessions/{id}", s.handleMultisignCancel)
	}
	if s.portal {
		mux.HandleFunc("GET /verify/portal", s.handlePortal)
		mux.HandleFunc("POST /verify/portal", s.handlePortalVerify)
	}
	if s.challenge != nil {
		mux.HandleFunc("POST /challenge", s.handleChallengeIssue)
		mux.HandleFunc("POST /challenge/confirm", s.handleChallengeConfirm)
	}
	if s.qr != nil {
		mux.HandleFunc("POST /qr/sessions", s.handleQRCreate)
		mux.HandleFunc("GET /qr/sessions/{id}", s.handleQRGet)
		// App-facing (public): eGov Mobile fetches data-to-sign and returns the
		// signature. The unguessable session id in the path is the capability token.
		mux.HandleFunc("GET /qr/a/{id}", s.handleQRAppData)
		mux.HandleFunc("POST /qr/a/{id}", s.handleQRAppSubmit)
	}
	return withLocale(mux)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req dto.SignRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := req.ToCore()
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "Sign"}, err.Error())
		return
	}
	out, err := s.svc.Sign(r.Context(), in)
	if err != nil {
		writeError(w, r, err, "")
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
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "Verify"}, err.Error())
		return
	}
	// Asking for the page implies asking for the card it renders, so a caller does
	// not have to set both.
	html := wantsHTML(r)
	if html {
		in.Report = true
	}
	out, err := s.svc.Verify(r.Context(), in)
	if err != nil {
		writeError(w, r, err, "")
		return
	}
	if html && writeReportHTML(w, out) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleArchive embeds long-term validation evidence into an existing signature.
func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	var req dto.ArchiveRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.svc.Archive(r.Context(), req.ToCore())
	if err != nil {
		writeError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleVerifyAt(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyAtRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := req.ToCore()
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "VerifyAt"}, err.Error())
		return
	}
	out, err := s.svc.VerifyAt(r.Context(), in)
	if err != nil {
		writeError(w, r, err, "")
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
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "Extract"}, err.Error())
		return
	}
	out, err := s.svc.Extract(r.Context(), in)
	if err != nil {
		writeError(w, r, err, "")
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
		writeError(w, r, err, "")
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
		writeError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// decode reads a JSON body, writing a 400 on failure. It reports success.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "decode"}, "invalid JSON body: "+err.Error())
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
// friendly message/action from the error catalog, in the language the request
// asked for. msg overrides the message when non-empty (used for pre-service
// request validation, which has no catalog entry).
func writeError(w http.ResponseWriter, r *http.Request, err error, msg string) {
	kind := core.KindInternal
	var de *core.Error
	if errors.As(err, &de) {
		kind = de.Kind
	}
	exp := core.ExplainIn(r.Context(), err)
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
