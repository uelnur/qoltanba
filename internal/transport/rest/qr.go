package rest

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/qr"
)

// QR endpoints orchestrate eGov Mobile signing/auth without a frontend: the
// consumer POSTs /qr/sessions to start a session (getting a base64 QR to render),
// polls GET /qr/sessions/{id} for the verified result or OIDC tokens, while eGov
// Mobile hits the public app-facing GET/POST /qr/a/{id} to fetch the data-to-sign
// and return the signature. Status responses carry the client-safe View only.

func (s *Server) handleQRCreate(w http.ResponseWriter, r *http.Request) {
	var req qr.CreateRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.qr.Create(r.Context(), req, publicBaseURL(r, s.qrBase))
	if err != nil {
		writeQRError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleQRGet(w http.ResponseWriter, r *http.Request) {
	v, err := s.qr.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeQRError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleQRAppData(w http.ResponseWriter, r *http.Request) {
	data, err := s.qr.AppData(r.Context(), r.PathValue("id"))
	if err != nil {
		writeQRError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) handleQRAppSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "qr"}, "read body: "+err.Error())
		return
	}
	if err := s.qr.SubmitSignature(r.Context(), r.PathValue("id"), body); err != nil {
		writeQRError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
}

// writeQRError maps a QR flow error to an HTTP status and the standard envelope.
func writeQRError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, qr.ErrSessionNotFound), errors.Is(err, qr.ErrAppOnly):
		writeJSON(w, http.StatusNotFound, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindInvalid), Message: "session not found"}})
	case errors.Is(err, qr.ErrSessionUsed), errors.Is(err, qr.ErrSessionExpired):
		writeJSON(w, http.StatusConflict, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindInvalid), Message: err.Error()}})
	case errors.Is(err, qr.ErrAuthUnavailable):
		writeJSON(w, http.StatusNotImplemented, errorBody{Error: errorDetail{
			Kind: core.KindName(core.KindUnsupported), Message: err.Error(),
			Action: "Enable the OIDC provider (oidc.enabled) to use auth-mode QR."}})
	case errors.Is(err, qr.ErrSignatureRejected), errors.Is(err, qr.ErrCertRevoked),
		errors.Is(err, qr.ErrNoData), errors.Is(err, qr.ErrUnsupportedMode),
		errors.Is(err, qr.ErrUnsupportedProfile):
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: "qr"}, err.Error())
	default:
		// Domain/driver faults keep their catalog-mapped status and message.
		writeError(w, err, "")
	}
}

// publicBaseURL resolves the externally reachable base URL for app-facing QR links.
// It prefers the configured value (authoritative behind a reverse proxy), else
// derives it from the X-Forwarded-* headers the proxy sets, else the request host.
func publicBaseURL(r *http.Request, configured string) string {
	if configured != "" {
		return strings.TrimRight(configured, "/")
	}
	proto := firstForwarded(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	prefix := strings.TrimRight(firstForwarded(r.Header.Get("X-Forwarded-Prefix")), "/")
	return proto + "://" + host + prefix
}

// firstForwarded returns the first token of a possibly comma-separated forwarded
// header value (proxies may chain them).
func firstForwarded(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
