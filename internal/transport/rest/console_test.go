package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// TestConsoleIsOffByDefault keeps a UI from appearing on a headless service
// without someone asking for it.
func TestConsoleIsOffByDefault(t *testing.T) {
	s := New(core.New(&fake.Provider{}))
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/console", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestConsoleRenders(t *testing.T) {
	s := New(core.New(&fake.Provider{}), WithConsole())
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/console", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"/verify", "/cert/validate", "/verify/registry"} {
		if !strings.Contains(body, want) {
			t.Errorf("console does not offer %q", want)
		}
	}
	// Without a sandbox key the console must not advertise demo signing.
	if strings.Contains(body, "/sandbox/sign") {
		t.Error("console offers sandbox signing while no key is configured")
	}
	for _, forbidden := range []string{"https://cdn", "unpkg", "googleapis"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("console pulls in %q", forbidden)
		}
	}
}

func TestConsoleOffersSandboxWhenConfigured(t *testing.T) {
	s := New(core.New(&fake.Provider{}), WithConsole(), WithSandboxKey("/tmp/demo.p12", "pw"))
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/console", nil))

	if !strings.Contains(w.Body.String(), "/sandbox/sign") {
		t.Error("console should offer demo signing when a sandbox key is set")
	}
}

// TestSandboxSignsWithTheConfiguredKey pins that the caller never supplies key
// material — that is the whole point of the sandbox.
func TestSandboxSignsWithTheConfiguredKey(t *testing.T) {
	prov := &fake.Provider{
		Caps:       provider.Capabilities{SignCMS: true},
		SignResult: provider.SignResult{Signature: []byte("sig")},
	}
	s := New(core.New(prov, core.WithKeySource(pathKeys{})), WithSandboxKey("/tmp/demo.p12", "pw"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sandbox/sign", strings.NewReader(`{"data":"aGVsbG8="}`))
	r.Header.Set("Content-Type", "application/json")
	s.Routes().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signature") {
		t.Errorf("body = %s", w.Body.String())
	}
}

func TestSandboxIsOffWithoutAKey(t *testing.T) {
	s := New(core.New(&fake.Provider{}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sandbox/sign", strings.NewReader(`{"data":"aGk="}`))
	r.Header.Set("Content-Type", "application/json")
	s.Routes().ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 without a sandbox key", w.Code)
	}
}

func TestSandboxRequiresData(t *testing.T) {
	s := New(core.New(&fake.Provider{}), WithSandboxKey("/tmp/demo.p12", "pw"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sandbox/sign", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	s.Routes().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// pathKeys resolves a path key spec straight through, standing in for the real
// key source.
type pathKeys struct{}

func (pathKeys) Resolve(context.Context, core.KeySpec) (core.KeyHandle, error) {
	return core.KeyHandle{}, nil
}
