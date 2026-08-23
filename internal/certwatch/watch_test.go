package certwatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// writeCert writes a self-signed certificate valid until notAfter and returns the
// directory holding it.
func writeCert(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2A),
		Subject:      pkix.Name{CommonName: "ТЕСТОВ ТЕСТ"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name), blob, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// stubValidator answers revocation checks from a fixed outcome.
type stubValidator struct {
	revoked bool
	libErr  *core.LibError
	calls   int
}

func (s *stubValidator) CertInfo(context.Context, core.CertInfoInput) (core.CertInfoOutput, error) {
	return core.CertInfoOutput{}, nil
}

func (s *stubValidator) Validate(context.Context, core.ValidateInput) (core.ValidateOutput, error) {
	s.calls++
	return core.ValidateOutput{Status: core.RevocationStatus{Revoked: s.revoked, LibError: s.libErr}}, nil
}

func TestSweepReportsExpiryAndRevocation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	writeCert(t, dir, "healthy.pem", now.Add(200*24*time.Hour))
	writeCert(t, dir, "soon.pem", now.Add(10*24*time.Hour))
	writeCert(t, dir, "gone.pem", now.Add(-time.Hour))

	v := &stubValidator{}
	w := New(v, Config{Dir: dir, WarnFrom: 30 * 24 * time.Hour, Now: func() time.Time { return now }})
	w.Sweep(context.Background())

	states := w.States()
	if len(states) != 3 {
		t.Fatalf("states = %d, want 3", len(states))
	}
	byFile := map[string]State{}
	for _, s := range states {
		byFile[s.File] = s
	}
	if got := byFile["healthy.pem"]; got.Subject != "ТЕСТОВ ТЕСТ" || got.ExpiresIn <= 0 {
		t.Errorf("healthy = %+v", got)
	}
	if kind := eventKind(byFile["healthy.pem"], 30*24*time.Hour); kind != "" {
		t.Errorf("healthy raised %q", kind)
	}
	if kind := eventKind(byFile["soon.pem"], 30*24*time.Hour); kind != "expiring" {
		t.Errorf("soon = %q, want expiring", kind)
	}
	if kind := eventKind(byFile["gone.pem"], 30*24*time.Hour); kind != "expired" {
		t.Errorf("gone = %q, want expired", kind)
	}
	// Revocation was not requested, so the responder must not have been touched.
	if v.calls != 0 {
		t.Errorf("revocation checked %d times while disabled", v.calls)
	}
}

func TestSweepChecksRevocationWhenEnabled(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeCert(t, dir, "signer.pem", now.Add(200*24*time.Hour))

	v := &stubValidator{revoked: true}
	w := New(v, Config{Dir: dir, CheckRevocation: true, Now: func() time.Time { return now }})
	w.Sweep(context.Background())

	got := w.States()[0]
	if !got.Revoked || v.calls != 1 {
		t.Fatalf("state = %+v after %d checks", got, v.calls)
	}
	if kind := eventKind(got, defaultWarnFrom); kind != "revoked" {
		t.Errorf("kind = %q, want revoked", kind)
	}
}

// TestInconclusiveRevocationIsNotHealthy pins the honest reading: an unreachable
// responder is recorded as a failed check, never as "not revoked".
func TestInconclusiveRevocationIsNotHealthy(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeCert(t, dir, "signer.pem", now.Add(200*24*time.Hour))

	v := &stubValidator{libErr: &core.LibError{Message: "responder unreachable"}}
	w := New(v, Config{Dir: dir, CheckRevocation: true, Now: func() time.Time { return now }})
	w.Sweep(context.Background())

	got := w.States()[0]
	if got.Error == "" || got.Revoked {
		t.Fatalf("state = %+v, want a recorded check failure", got)
	}
	if kind := eventKind(got, defaultWarnFrom); kind != "check_failed" {
		t.Errorf("kind = %q, want check_failed", kind)
	}
}

// TestWebhookFiresOnChangeOnly keeps an operator from being paged on every sweep
// while nothing moves.
func TestWebhookFiresOnChangeOnly(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeCert(t, dir, "soon.pem", now.Add(5*24*time.Hour))

	var mu sync.Mutex
	var events []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	w := New(&stubValidator{}, Config{
		Dir: dir, WarnFrom: 30 * 24 * time.Hour, WebhookURL: srv.URL,
		Now: func() time.Time { return now }, HTTP: srv.Client(),
	})
	w.Sweep(context.Background())
	w.Sweep(context.Background())
	w.Sweep(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("webhook fired %d times across three sweeps, want 1", len(events))
	}
	if events[0].Kind != "expiring" || events[0].State.Subject == "" {
		t.Errorf("event = %+v", events[0])
	}
}

func TestUnreadableFileIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "junk.pem"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	w := New(&stubValidator{}, Config{Dir: dir})
	w.Sweep(context.Background())

	got := w.States()[0]
	if got.Error == "" {
		t.Error("a file that is not a certificate must be reported, not ignored")
	}
}
