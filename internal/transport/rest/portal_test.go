package rest

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func TestFormatOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want core.SignatureFormat
	}{
		{"xml prolog", []byte(`<?xml version="1.0"?><root/>`), core.FormatXML},
		{"xml with leading whitespace", []byte("\n  <Signature/>"), core.FormatXML},
		{"pem cms", []byte("-----BEGIN CMS-----"), core.FormatCMS},
		{"der cms", []byte{0x30, 0x82, 0x01}, core.FormatCMS},
		{"empty", nil, core.FormatCMS},
	} {
		if got := formatOf(tc.in); got != tc.want {
			t.Errorf("%s: formatOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// portalRequest builds a multipart upload the way a browser form would.
func portalRequest(t *testing.T, signature, document []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if signature != nil {
		f, _ := mw.CreateFormFile("signature", "doc.p7s")
		_, _ = f.Write(signature)
	}
	if document != nil {
		f, _ := mw.CreateFormFile("document", "doc.pdf")
		_, _ = f.Write(document)
	}
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/verify/portal", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestPortalRendersTheCard(t *testing.T) {
	svc := core.New(&fake.Provider{
		VerifyResult: provider.VerifyResult{Valid: true},
		Props:        fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТОВ ТЕСТ"}),
	})
	s := New(svc, WithPortal())

	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, portalRequest(t, []byte("cms-bytes"), []byte("document")))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if body := w.Body.String(); !strings.Contains(body, "verdict") {
		t.Errorf("portal did not render the verification card: %s", body)
	}
}

// TestPortalRequiresASignature keeps the page from silently verifying nothing.
func TestPortalRequiresASignature(t *testing.T) {
	s := New(core.New(&fake.Provider{}), WithPortal())

	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, portalRequest(t, nil, []byte("document")))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Выберите файл подписи") {
		t.Error("the page should say what is missing")
	}
}

// TestPortalIsOffByDefault pins the deliberate exposure: the page accepts uploads
// from anyone who can reach it, so enabling REST must not enable it.
func TestPortalIsOffByDefault(t *testing.T) {
	s := New(core.New(&fake.Provider{}))

	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verify/portal", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 while the portal is disabled", w.Code)
	}
}

func TestPortalPageRenders(t *testing.T) {
	s := New(core.New(&fake.Provider{}), WithPortal())

	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verify/portal", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`name="signature"`, `name="document"`, "enctype=\"multipart/form-data\""} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page is missing %q", want)
		}
	}
}
