package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// caWithCRL builds a CA key/cert and returns a leaf certificate (DER) whose CRL
// distribution point is dpURL, plus a helper to mint a CRL with a given
// nextUpdate signed by that CA.
func caWithCRL(t *testing.T, dpURL string) (leafDER []byte, makeCRL func(next time.Time) []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CRL CA"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	if dpURL != "" {
		leafTmpl.CRLDistributionPoints = []string{dpURL}
	}
	leafDER, _ = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)

	makeCRL = func(next time.Time) []byte {
		tmpl := &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: time.Unix(1_600_000_000, 0), NextUpdate: next,
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
		if err != nil {
			t.Fatalf("create CRL: %v", err)
		}
		return der
	}
	return leafDER, makeCRL
}

func TestCRLFor_FetchesAndCachesUntilNextUpdate(t *testing.T) {
	const url = "https://x/leaf.crl"
	leaf, makeCRL := caWithCRL(t, url)
	now := time.Unix(1_600_000_100, 0)
	crlDER := makeCRL(now.Add(time.Hour)) // nextUpdate in the future

	fetches := 0
	c := New(0)
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, got string) ([]byte, bool) {
		if got != url {
			t.Errorf("fetched %q, want %q", got, url)
		}
		fetches++
		return crlDER, true
	}

	if der, ok := c.CRLFor(context.Background(), leaf); !ok || len(der) == 0 {
		t.Fatalf("CRLFor first = (%d bytes, %v), want a CRL", len(der), ok)
	}
	// Second lookup within nextUpdate must hit the cache, not refetch.
	if _, ok := c.CRLFor(context.Background(), leaf); !ok {
		t.Fatal("CRLFor second failed")
	}
	if fetches != 1 {
		t.Errorf("fetches = %d, want 1 (cached within nextUpdate)", fetches)
	}
}

func TestCRLFor_RefetchesAfterNextUpdate(t *testing.T) {
	const url = "https://x/leaf.crl"
	leaf, makeCRL := caWithCRL(t, url)
	cur := time.Unix(1_600_000_100, 0)
	crlDER := makeCRL(cur.Add(time.Minute))

	fetches := 0
	c := New(0)
	c.now = func() time.Time { return cur }
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) { fetches++; return crlDER, true }

	c.CRLFor(context.Background(), leaf)
	cur = cur.Add(time.Hour) // now past nextUpdate → must refetch
	c.CRLFor(context.Background(), leaf)
	if fetches != 2 {
		t.Errorf("fetches = %d, want 2 (refetch past nextUpdate)", fetches)
	}
}

func TestCRLFor_StaleFallbackOnFetchFailure(t *testing.T) {
	const url = "https://x/leaf.crl"
	leaf, makeCRL := caWithCRL(t, url)
	cur := time.Unix(1_600_000_100, 0)
	crlDER := makeCRL(cur.Add(time.Minute))

	ok := true
	c := New(0)
	c.now = func() time.Time { return cur }
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) {
		if ok {
			return crlDER, true
		}
		return nil, false
	}

	c.CRLFor(context.Background(), leaf) // populates cache
	ok = false
	cur = cur.Add(time.Hour) // stale, and refetch now fails
	if der, got := c.CRLFor(context.Background(), leaf); !got || len(der) == 0 {
		t.Errorf("CRLFor = (%d bytes, %v), want stale-but-available fallback", len(der), got)
	}
}

func TestCRLFor_NoDistributionPointIsMiss(t *testing.T) {
	// A cert without CRL DP: leaf built with an empty dpURL yields no points.
	leaf, _ := caWithCRL(t, "")
	c := New(0)
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) {
		t.Fatal("fetch must not be called when there is no distribution point")
		return nil, false
	}
	if _, ok := c.CRLFor(context.Background(), leaf); ok {
		t.Error("CRLFor ok = true, want miss for a cert without CRL DP")
	}
}
