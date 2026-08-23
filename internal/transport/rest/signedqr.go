package rest

import (
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/signedqr"
)

// Signed-document QR: POST /qr/documents issues a QR that carries a short signed
// statement, POST /qr/documents/verify checks a scanned one.
//
// Verification is deliberately open to whoever can reach it — checking a permit
// is what a checkpoint does, and it needs no key. Issuing is not: it signs with
// the service key, so it belongs behind whatever guards the deployment already
// has in front of its API.

func (s *Server) handleSignedQRIssue(w http.ResponseWriter, r *http.Request) {
	var req signedqr.IssueRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.signedQR.Issue(req)
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInvalid, Op: "SignedQRIssue"}, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSignedQRVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload string `json:"payload"`
	}
	if !decode(w, r, &req) {
		return
	}
	// A forged or expired document is the answer, not an error: 200 with
	// valid=false is what a scanner app needs to display.
	writeJSON(w, http.StatusOK, s.signedQR.Verify(req.Payload))
}
