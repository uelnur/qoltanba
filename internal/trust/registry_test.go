package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/pki"
)

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
}

func TestLoadRegistry_MixedResults(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := caTmpl("Reg Root")
	root, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(root)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interDER, _ := x509.CreateCertificate(rand.Reader, caTmpl("Reg Inter"), rootCert, &interKey.PublicKey, rootKey)
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	// A fetch func mapping URLs to bodies: one DER, one PEM, one failing, one junk.
	bodies := map[string][]byte{
		"https://x/root.cer":  root,
		"https://x/inter.pem": interPEM,
		"https://x/junk.cer":  []byte("not a cert"),
	}
	fetch := func(_ context.Context, url string) ([]byte, bool) {
		b, ok := bodies[url]
		return b, ok
	}
	refs := []pki.CACertRef{
		{Label: "root", URL: "https://x/root.cer"},
		{Label: "inter", URL: "https://x/inter.pem"},
		{Label: "missing", URL: "https://x/missing.cer"}, // fetch fails
		{Label: "junk", URL: "https://x/junk.cer"},       // parse fails
	}

	store := Empty()
	errs := store.LoadRegistry(context.Background(), refs, fetch)
	if len(errs) != 2 {
		t.Fatalf("errors = %d, want 2 (missing + junk)", len(errs))
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
