package rest

import (
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
)

// The sandbox signs with a demo key the operator configured, so someone
// evaluating the service can produce a signature — and then verify it — without
// having an ЭЦП of their own yet.
//
// It is a deliberate hole in the usual rule that the service never signs with a
// key the caller did not supply, so it is off unless a key is configured, it
// signs only what the caller sends, and the key is meant to be a test container:
// anyone who can reach the endpoint can sign arbitrary bytes with it.

func (s *Server) handleSandboxSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data   []byte `json:"data"`
		Format string `json:"format,omitempty"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Data) == 0 {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "SandboxSign"}, "data is required")
		return
	}
	format := core.SignatureFormat(req.Format)
	if format == "" {
		format = core.FormatCMS
	}

	out, err := s.svc.Sign(r.Context(), core.SignInput{
		Format:    format,
		Data:      req.Data,
		OutputPEM: true,
		Key: core.KeySpec{Path: &core.PathKey{
			Path:     s.sandboxKey,
			Password: s.sandboxPass,
		}},
		// A demo key is often expired or issued by a test CA; refusing to sign with
		// it would defeat the point of the sandbox.
		NoCheckCertTime: true,
	})
	if err != nil {
		writeError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
