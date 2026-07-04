package core

import (
	"bytes"
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
)

// mapFetcher resolves an issuer by subject-DN from an in-memory table (no
// network), standing in for the AIA fetcher in tests.
type mapFetcher map[string][]byte // key: issuer RawSubject → issuer DER

func (m mapFetcher) FetchIssuer(_ context.Context, certDER []byte) ([]byte, bool) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, false
	}
	der, ok := m[string(c.RawIssuer)]
	return der, ok
}

type testCert struct {
	der  []byte
	pem  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func makeCert(t *testing.T, cn string, parent *testCert, isCA bool) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + int64(len(cn))),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
		IsCA:         isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	}
	signer, signerKey, signerPub := tmpl, key, any(&key.PublicKey)
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, signerPub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCert{
		der:  der,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert: c,
		key:  key,
	}
}

func TestBuildChain_CompleteAndAnchored(t *testing.T) {
	root := makeCert(t, "Test Root", nil, true)
	inter := makeCert(t, "Test Intermediate", &root, true)
	leaf := makeCert(t, "Test Leaf", &inter, false)

	leafFull := Certificate{PEM: leaf.pem, Subject: Subject{CommonName: "Test Leaf"}}
	trusted := []TrustedCert{
		{Cert: root.pem, Intermediate: false},
		{Cert: inter.pem, Intermediate: true},
	}

	chain, complete, anchored := buildChain(context.Background(), leafFull, leaf.der, trusted, nil)
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3 (leaf, inter, root)", len(chain))
	}
	if chain[1].Subject.CommonName != "Test Intermediate" || chain[2].Subject.CommonName != "Test Root" {
		t.Errorf("chain order wrong: %q, %q", chain[1].Subject.CommonName, chain[2].Subject.CommonName)
	}
	if !complete {
		t.Error("expected complete chain (reached self-signed root)")
	}
	if !anchored {
		t.Error("expected trust anchor found")
	}
	if !chain[2].IsCA {
		t.Error("root node should be marked IsCA")
	}
}

func TestBuildChain_IncompleteWithoutRoot(t *testing.T) {
	root := makeCert(t, "Test Root", nil, true)
	inter := makeCert(t, "Test Intermediate", &root, true)
	leaf := makeCert(t, "Test Leaf", &inter, false)

	// Only the intermediate is trusted — chain reaches it but not a root.
	trusted := []TrustedCert{{Cert: inter.pem, Intermediate: true}}
	chain, complete, anchored := buildChain(context.Background(), Certificate{PEM: leaf.pem}, leaf.der, trusted, nil)

	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf, inter)", len(chain))
	}
	if complete {
		t.Error("expected incomplete chain (no root)")
	}
	if !anchored {
		t.Error("intermediate is a configured anchor → anchored should be true")
	}
}

func TestBuildChain_AIAFetchCompletes(t *testing.T) {
	root := makeCert(t, "Test Root", nil, true)
	inter := makeCert(t, "Test Intermediate", &root, true)
	leaf := makeCert(t, "Test Leaf", &inter, false)

	// Nothing trusted; the fetcher supplies the missing issuers keyed by the
	// subject DN of the issuer being resolved (== the child's RawIssuer).
	fetcher := mapFetcher{
		string(inter.cert.RawSubject): inter.der, // leaf's issuer is the intermediate
		string(root.cert.RawSubject):  root.der,  // intermediate's issuer is the root
	}
	chain, complete, anchored := buildChain(context.Background(), Certificate{PEM: leaf.pem}, leaf.der, nil, fetcher)

	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3 via AIA", len(chain))
	}
	if !complete {
		t.Error("expected complete chain after AIA fetch to root")
	}
	// Fetched certs are not trust anchors (nothing configured as trusted).
	if anchored {
		t.Error("fetched issuers must not count as trust anchors")
	}
	// Signature verification confirms the ECDSA links resolved correctly.
	if !bytes.Equal(chain[2].PEM, root.pem) {
		t.Error("top of chain should be the root")
	}
}

func TestBuildChain_NoTrustedNoChain(t *testing.T) {
	root := makeCert(t, "Test Root", nil, true)
	inter := makeCert(t, "Test Intermediate", &root, true)
	leaf := makeCert(t, "Test Leaf", &inter, false) // issuer not in the trusted set
	chain, complete, anchored := buildChain(context.Background(), Certificate{PEM: leaf.pem}, leaf.der, nil, nil)
	if len(chain) != 1 || complete || anchored {
		t.Errorf("expected leaf-only chain with no trust: len=%d complete=%v anchored=%v", len(chain), complete, anchored)
	}
}
