package rest

import (
	"net/http"
	"os"
	"time"

	"github.com/uelnur/qoltanba/internal/audit"
	"github.com/uelnur/qoltanba/internal/core"
)

// Audit endpoints expose the journal for review: GET /audit/verify walks the
// chain and reports whether — and where — it was altered, GET /audit/export
// streams it for a SIEM.
//
// Both read the journal file directly rather than an in-memory copy: an auditor
// checks what is on disk, which is the artifact that would be tampered with.

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(s.auditPath)
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindUnavailable, Op: "AuditVerify"}, err.Error())
		return
	}
	defer f.Close()

	// The signature check needs the service key; without one the chain is still
	// checked, which catches edits but not a wholesale re-seal.
	res := audit.Verify(f, s.auditVerifier)
	status := http.StatusOK
	if !res.Intact {
		// A broken chain is a finding, not a server fault: 409 says "the state you
		// asked about is not what it should be".
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(s.auditPath)
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindUnavailable, Op: "AuditExport"}, err.Error())
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	var modTime time.Time
	if info, err := f.Stat(); err == nil {
		modTime = info.ModTime()
	}
	// ServeContent gives range requests and conditional fetches for free, which is
	// what a SIEM tailing the journal wants.
	http.ServeContent(w, r, "audit.jsonl", modTime, f)
}
