package dataref

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
)

func kindOf(t *testing.T, err error) core.ErrorKind {
	t.Helper()
	var de *core.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *core.Error", err)
	}
	return de.Kind
}

func TestLocalPath_GatedOffByDefault(t *testing.T) {
	r := New(Config{}) // AllowLocalPath false
	_, err := r.Resolve(context.Background(), core.DataRef{Path: "/etc/hosts"})
	if kindOf(t, err) != core.KindInvalid {
		t.Fatalf("kind = %v, want invalid", kindOf(t, err))
	}
}

func TestLocalPath_Allowed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{AllowLocalPath: true})
	rd, err := r.Resolve(context.Background(), core.DataRef{Path: p})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rd.Path != p {
		t.Errorf("path = %q, want %q", rd.Path, p)
	}
	rd.Release() // caller-owned file must survive release
	if _, err := os.Stat(p); err != nil {
		t.Errorf("caller's file was removed on Release: %v", err)
	}
}

func TestLocalPath_TooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	_ = os.WriteFile(p, make([]byte, 100), 0o600)
	r := New(Config{AllowLocalPath: true, MaxBytes: 10})
	_, err := r.Resolve(context.Background(), core.DataRef{Path: p})
	if kindOf(t, err) != core.KindInvalid {
		t.Fatalf("kind = %v, want invalid", kindOf(t, err))
	}
}

func TestURL_GatedOffByDefault(t *testing.T) {
	r := New(Config{}) // AllowURL false
	_, err := r.Resolve(context.Background(), core.DataRef{URL: "https://example/data"})
	if kindOf(t, err) != core.KindInvalid {
		t.Fatalf("kind = %v, want invalid", kindOf(t, err))
	}
}

func TestURL_FetchToSpoolAndCleanup(t *testing.T) {
	body := []byte("streamed-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	r := New(Config{AllowURL: true, AllowedSchemes: []string{"http"}})
	rd, err := r.Resolve(context.Background(), core.DataRef{URL: srv.URL})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := os.ReadFile(rd.Path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("spool content = %q, want %q", got, body)
	}
	// The spool file must be private (0600).
	info, _ := os.Stat(rd.Path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("spool perm = %o, want 600", info.Mode().Perm())
	}
	rd.Release()
	if _, err := os.Stat(rd.Path); !os.IsNotExist(err) {
		t.Errorf("spool file survived Release")
	}
}

func TestURL_SchemeRejected(t *testing.T) {
	r := New(Config{AllowURL: true}) // default schemes = [https]
	_, err := r.Resolve(context.Background(), core.DataRef{URL: "http://example/data"})
	if kindOf(t, err) != core.KindInvalid {
		t.Fatalf("kind = %v, want invalid", kindOf(t, err))
	}
}

func TestURL_TooLargeCleansSpool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 100))
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := New(Config{AllowURL: true, AllowedSchemes: []string{"http"}, MaxBytes: 10, SpoolDir: dir})
	_, err := r.Resolve(context.Background(), core.DataRef{URL: srv.URL})
	if kindOf(t, err) != core.KindInvalid {
		t.Fatalf("kind = %v, want invalid", kindOf(t, err))
	}
	// No spool file must be left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("spool dir has %d leftover files, want 0", len(entries))
	}
}
