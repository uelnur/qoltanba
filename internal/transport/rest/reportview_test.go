package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

func TestWantsHTML(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"application/json", false},
		{"text/html", true},
		{"text/html,application/xhtml+xml", true},
		// A browser-style header that also lists JSON must not switch a JSON client
		// to HTML by accident.
		{"application/json, text/html", false},
		{"text/plain", false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/verify", nil)
		if tc.accept != "" {
			r.Header.Set("Accept", tc.accept)
		}
		if got := wantsHTML(r); got != tc.want {
			t.Errorf("wantsHTML(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}

func TestWriteReportHTML(t *testing.T) {
	signed := time.Unix(1_700_000_000, 0).UTC()
	out := core.VerifyOutput{Valid: true, Report: &core.VerificationReport{
		Verdict:   core.VerdictValid,
		Summary:   "Signature is valid; signed by ТЕСТОВ ТЕСТ.",
		CheckedAt: signed,
		Document:  core.ReportDocument{Format: core.FormatCMS, SignatureSHA256: "abc123"},
		Signers: []core.ReportSigner{{
			Name: "ТЕСТОВ ТЕСТ", IIN: "123456789011", SignedAt: &signed, SignedAtSource: "timestamp",
			Certificate: core.ReportCertificate{SerialNumber: "1f2e", Issuer: "НУЦ"},
		}},
		Steps: []core.DiagnosisStep{{Step: "signature", Status: core.DiagPass, Summary: "Signature is valid."}},
	}}

	w := httptest.NewRecorder()
	if !writeReportHTML(w, out) {
		t.Fatal("report was not rendered")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"ТЕСТОВ ТЕСТ", "123456789011", "abc123", "valid", "timestamp", "НУЦ"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}
	// Self-contained: an audit artifact must render on an air-gapped machine.
	for _, forbidden := range []string{"http://", "https://", "<script"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("page pulls in %q — it must be self-contained", forbidden)
		}
	}
}

// TestWriteReportHTMLWithoutReport keeps the endpoint honest: with nothing to
// render it must fall back to JSON rather than emit an empty page.
func TestWriteReportHTMLWithoutReport(t *testing.T) {
	w := httptest.NewRecorder()
	if writeReportHTML(w, core.VerifyOutput{Valid: true}) {
		t.Error("rendered a page without a report")
	}
}
