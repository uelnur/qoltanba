//go:build qoltanba_functional

// Functional tests against the REAL Kalkan library. They are not part of normal
// CI: they need the native library (BYOL) and a test key, and run behind the
// qoltanba_functional build tag in a linux/amd64 environment with LD_PRELOAD set
// up (see test/functional/). Tests are split by feature (capabilities, signing,
// certificates, hash, revocation, concurrency, misc); this file holds the shared
// harness. Paths and password come from the environment:
//
//	QOLTANBA_LIB   path to libkalkancryptwr-64.so
//	QOLTANBA_KEY   path to a test .p12
//	QOLTANBA_KEY2  path to a second .p12 (optional, for multi-signature)
//	QOLTANBA_PASS  container password (default Qwerty12)
//	QOLTANBA_POOL  pool size (default 4 for the isolation test)
package native

import (
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

var testData = []byte("Hello, Qazaqstan 2026 — qoltanba driver functional test")

// trustedCAs reads the test CAs from the environment (paths to .cer). XML
// verification needs them.
func trustedCAs(t *testing.T) []provider.TrustedCert {
	t.Helper()
	var cas []provider.TrustedCert
	for _, e := range []struct {
		env   string
		inter bool
	}{{"QOLTANBA_CA_ROOT", false}, {"QOLTANBA_CA_NCA", true}} {
		path := os.Getenv(e.env)
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Logf("CA %s unavailable: %v", path, err)
			continue
		}
		cas = append(cas, provider.TrustedCert{Cert: b, Intermediate: e.inter})
	}
	return cas
}

// isolationDeps collects the isolated-namespace dependencies from the
// environment (iconv shim, libkalkancrypto, libm, libpcsclite).
func isolationDeps() []string {
	get := func(env, def string) string {
		if v := os.Getenv(env); v != "" {
			return v
		}
		return def
	}
	var deps []string
	for _, d := range []string{
		get("QOLTANBA_ICONV", "/opt/iconv_compat.so"),
		get("QOLTANBA_DEP", ""),
		get("QOLTANBA_LIBM", "/usr/lib/x86_64-linux-gnu/libm.so.6"),
		get("QOLTANBA_PCSC", "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1"),
	} {
		if d != "" {
			deps = append(deps, d)
		}
	}
	return deps
}

func envKey() provider.KeyRef {
	pass := os.Getenv("QOLTANBA_PASS")
	if pass == "" {
		pass = "Qwerty12"
	}
	return provider.KeyRef{Storage: provider.StoragePKCS12, Path: os.Getenv("QOLTANBA_KEY"), Password: pass}
}

func openPool(t *testing.T, size int, isolated bool) *Pool {
	t.Helper()
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set — skipping functional tests (native library required)")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skipf("library unavailable (%v)", err)
	}
	p, err := Open(Config{
		WrapperPath:   lib,
		PoolSize:      size,
		Isolated:      isolated,
		IsolationDeps: isolationDeps(),
	})
	if err != nil {
		t.Fatalf("Open(size=%d, isolated=%v): %v", size, isolated, err)
	}
	return p
}
