package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDir_ClassifiesRootVsIntermediate(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root"},
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "root.pem"), rootDER)
	writePEM(t, filepath.Join(dir, "inter.crt"), interDER)
	// A non-cert file must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	anchors := store.Anchors()
	if len(anchors) != 2 {
		t.Fatalf("anchors = %d, want 2", len(anchors))
	}

	var roots, inters int
	for _, a := range anchors {
		if a.Intermediate {
			inters++
		} else {
			roots++
		}
	}
	if roots != 1 || inters != 1 {
		t.Errorf("classification roots=%d inters=%d, want 1/1", roots, inters)
	}
}

func TestLoadDir_MissingIsEmpty(t *testing.T) {
	store, err := LoadDir(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("LoadDir missing: %v", err)
	}
	if len(store.Anchors()) != 0 {
		t.Errorf("expected empty store")
	}
}
