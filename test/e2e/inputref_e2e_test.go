//go:build qoltanba_functional

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/dataref"
	"github.com/uelnur/qoltanba/internal/keysource"
	"github.com/uelnur/qoltanba/internal/native"
)

// TestFunctionalE2E_SignByReferenceFile signs a file by reference (KC_IN_FILE):
// the driver reads the content from the path instead of an inline buffer. It
// exercises the input-by-reference path end-to-end against real Kalkan.
func TestFunctionalE2E_SignByReferenceFile(t *testing.T) {
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set")
	}
	pool, err := native.Open(native.Config{WrapperPath: lib, PoolSize: 1})
	if err != nil {
		t.Fatalf("open driver: %v", err)
	}
	defer pool.Close()
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
		core.WithDataResolver(dataref.New(dataref.Config{AllowLocalPath: true})),
	)

	content := []byte("large-file-by-reference payload for KC_IN_FILE")
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// Detached CMS: the driver reads the content from the path, the signature
	// carries no content.
	out, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Detached: true, DataRef: core.DataRef{Path: path},
		Key: testKey(t), OutputPEM: true,
	})
	if err != nil {
		t.Fatalf("sign by reference: %v", err)
	}
	if len(out.Signature) == 0 {
		t.Fatal("empty signature")
	}

	// Verify the detached signature against the original content.
	v, err := svc.Verify(context.Background(), core.VerifyInput{
		Format: core.FormatCMS, Signature: out.Signature, Data: content, Detached: true, InputPEM: true,
	})
	if err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if !v.Valid {
		t.Fatalf("by-reference detached signature not valid; libError=%+v", v.LibError)
	}
}
