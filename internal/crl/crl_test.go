package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// testCA builds a CA and a leaf whose base CRL distribution point is baseURL and,
// when deltaURL is non-empty, whose Freshest-CRL (delta) point is deltaURL. It
// returns the leaf DER plus helpers to mint base and delta CRLs signed by the CA.
type testCA struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leaf   []byte
}

func newTestCA(t *testing.T, baseURL, deltaURL string) testCA {
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
	if baseURL != "" {
		leafTmpl.CRLDistributionPoints = []string{baseURL}
	}
	if deltaURL != "" {
		// FreshestCRL (2.5.29.46) is encoded exactly like CRLDistributionPoints;
		// borrow the DER Go emits for a CRLDistributionPoints ext at deltaURL.
		leafTmpl.ExtraExtensions = append(leafTmpl.ExtraExtensions, pkix.Extension{
			Id: oidFreshestCRL, Value: crlDPExtValue(t, deltaURL),
		})
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	return testCA{caCert: caCert, caKey: caKey, leaf: leafDER}
}

// makeBase mints a base CRL with the given CRLNumber and nextUpdate.
func (ca testCA) makeBase(t *testing.T, number int64, next time.Time) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Unix(1_600_000_000, 0), NextUpdate: next,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.caCert, ca.caKey)
	if err != nil {
		t.Fatalf("create base CRL: %v", err)
	}
	return der
}

// makeDelta mints a delta CRL carrying a BaseCRLNumber (delta indicator).
func (ca testCA) makeDelta(t *testing.T, number, baseNumber int64, next time.Time) []byte {
	t.Helper()
	indicator, err := asn1.Marshal(big.NewInt(baseNumber))
	if err != nil {
		t.Fatalf("marshal base number: %v", err)
	}
	tmpl := &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Unix(1_600_000_000, 0), NextUpdate: next,
		ExtraExtensions: []pkix.Extension{{Id: oidDeltaCRLIndicator, Value: indicator}},
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.caCert, ca.caKey)
	if err != nil {
		t.Fatalf("create delta CRL: %v", err)
	}
	return der
}

// crlDPExtValue builds the DER value of a CRLDistributionPoints/FreshestCRL
// extension for a single fullName URI — the structure parseDistributionPointURIs
// reads: SEQUENCE OF DistributionPoint { [0] { [0] { [6] IA5String } } }.
func crlDPExtValue(t *testing.T, url string) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(url))
					})
				})
			})
		})
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatalf("build distribution points: %v", err)
	}
	return der
}

func TestCRLFor_FetchesAndCachesUntilNextUpdate(t *testing.T) {
	const url = "https://x/leaf.crl"
	ca := newTestCA(t, url, "")
	now := time.Unix(1_600_000_100, 0)
	crlDER := ca.makeBase(t, 1, now.Add(time.Hour)) // nextUpdate in the future

	fetches := 0
	c := New(Config{})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, got string) ([]byte, bool) {
		if got != url {
			t.Errorf("fetched %q, want %q", got, url)
		}
		fetches++
		return crlDER, true
	}

	res, ok := c.CRLFor(context.Background(), ca.leaf)
	if !ok || len(res.Base) == 0 || !res.Reliable {
		t.Fatalf("CRLFor first = (%d bytes, ok=%v, reliable=%v), want a reliable CRL", len(res.Base), ok, res.Reliable)
	}
	// Second lookup within nextUpdate must hit the cache, not refetch.
	if _, ok := c.CRLFor(context.Background(), ca.leaf); !ok {
		t.Fatal("CRLFor second failed")
	}
	if fetches != 1 {
		t.Errorf("fetches = %d, want 1 (cached within nextUpdate)", fetches)
	}
}

func TestCRLFor_RefetchesAfterNextUpdate(t *testing.T) {
	const url = "https://x/leaf.crl"
	ca := newTestCA(t, url, "")
	cur := time.Unix(1_600_000_100, 0)
	crlDER := ca.makeBase(t, 1, cur.Add(time.Minute))

	fetches := 0
	c := New(Config{})
	c.now = func() time.Time { return cur }
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) { fetches++; return crlDER, true }

	c.CRLFor(context.Background(), ca.leaf)
	cur = cur.Add(time.Hour) // now past nextUpdate → must refetch
	c.CRLFor(context.Background(), ca.leaf)
	if fetches != 2 {
		t.Errorf("fetches = %d, want 2 (refetch past nextUpdate)", fetches)
	}
}

func TestCRLFor_StaleFallbackIsUnreliable(t *testing.T) {
	const url = "https://x/leaf.crl"
	ca := newTestCA(t, url, "")
	cur := time.Unix(1_600_000_100, 0)
	crlDER := ca.makeBase(t, 1, cur.Add(time.Minute))

	ok := true
	c := New(Config{})
	c.now = func() time.Time { return cur }
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) {
		if ok {
			return crlDER, true
		}
		return nil, false
	}

	c.CRLFor(context.Background(), ca.leaf) // populates cache
	ok = false
	cur = cur.Add(time.Hour) // stale, and refetch now fails
	res, got := c.CRLFor(context.Background(), ca.leaf)
	if !got || len(res.Base) == 0 {
		t.Fatalf("CRLFor = (%d bytes, %v), want stale-but-available fallback", len(res.Base), got)
	}
	if res.Reliable || res.Reason != "stale-base" {
		t.Errorf("stale CRL: reliable=%v reason=%q, want reliable=false reason=stale-base", res.Reliable, res.Reason)
	}
}

func TestCRLFor_NoDistributionPointIsMiss(t *testing.T) {
	ca := newTestCA(t, "", "") // no CRL DP
	c := New(Config{})
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) {
		t.Fatal("fetch must not be called when there is no distribution point")
		return nil, false
	}
	if _, ok := c.CRLFor(context.Background(), ca.leaf); ok {
		t.Error("CRLFor ok = true, want miss for a cert without CRL DP")
	}
}

func TestCRLFor_ConsistentDeltaIsReturned(t *testing.T) {
	const baseURL, deltaURL = "https://x/base.crl", "https://x/delta.crl"
	ca := newTestCA(t, baseURL, deltaURL)
	now := time.Unix(1_600_000_100, 0)
	base := ca.makeBase(t, 167, now.Add(time.Hour))
	delta := ca.makeDelta(t, 200, 167, now.Add(time.Hour)) // BaseCRLNumber 167 == base CRLNumber

	c := New(Config{})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, u string) ([]byte, bool) {
		switch u {
		case baseURL:
			return base, true
		case deltaURL:
			return delta, true
		}
		return nil, false
	}

	res, ok := c.CRLFor(context.Background(), ca.leaf)
	if !ok || !res.Reliable {
		t.Fatalf("CRLFor = (ok=%v reliable=%v reason=%q), want reliable", ok, res.Reliable, res.Reason)
	}
	if len(res.Delta) == 0 {
		t.Error("consistent delta was not returned for overlay")
	}
}

func TestCRLFor_InconsistentDeltaIsUnreliable(t *testing.T) {
	const baseURL, deltaURL = "https://x/base.crl", "https://x/delta.crl"
	ca := newTestCA(t, baseURL, deltaURL)
	now := time.Unix(1_600_000_100, 0)
	base := ca.makeBase(t, 166, now.Add(time.Hour))
	delta := ca.makeDelta(t, 200, 167, now.Add(time.Hour)) // needs base >= 167, we hold 166

	c := New(Config{})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, u string) ([]byte, bool) {
		switch u {
		case baseURL:
			return base, true
		case deltaURL:
			return delta, true
		}
		return nil, false
	}

	res, ok := c.CRLFor(context.Background(), ca.leaf)
	if !ok {
		t.Fatal("CRLFor not ok, want the base CRL to still be available")
	}
	if res.Reliable || res.Reason != "delta-inconsistent" {
		t.Errorf("reliable=%v reason=%q, want reliable=false reason=delta-inconsistent", res.Reliable, res.Reason)
	}
	if len(res.Delta) != 0 {
		t.Error("an inconsistent delta must not be returned for overlay")
	}
}

func TestCRLFor_DeltaUnavailableIsUnreliable(t *testing.T) {
	const baseURL, deltaURL = "https://x/base.crl", "https://x/delta.crl"
	ca := newTestCA(t, baseURL, deltaURL)
	now := time.Unix(1_600_000_100, 0)
	base := ca.makeBase(t, 167, now.Add(time.Hour))

	c := New(Config{})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, u string) ([]byte, bool) {
		if u == baseURL {
			return base, true
		}
		return nil, false // delta cannot be fetched
	}

	res, ok := c.CRLFor(context.Background(), ca.leaf)
	if !ok || res.Reliable || res.Reason != "delta-unavailable" {
		t.Errorf("CRLFor = (ok=%v reliable=%v reason=%q), want ok reliable=false reason=delta-unavailable", ok, res.Reliable, res.Reason)
	}
}

func TestSpool_PersistsAndWarmStarts(t *testing.T) {
	const url = "https://x/leaf.crl"
	ca := newTestCA(t, url, "")
	now := time.Unix(1_600_000_100, 0)
	crlDER := ca.makeBase(t, 1, now.Add(time.Hour))
	dir := t.TempDir()

	c := New(Config{SpoolDir: dir})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, _ string) ([]byte, bool) { return crlDER, true }
	if _, ok := c.CRLFor(context.Background(), ca.leaf); !ok {
		t.Fatal("first CRLFor failed")
	}

	// The body must live on disk, not only in memory.
	files, _ := filepath.Glob(filepath.Join(dir, "*.crl"))
	if len(files) != 1 {
		t.Fatalf("spool files = %d, want 1 on-disk CRL", len(files))
	}

	// A fresh cache over the same directory warm-starts and serves without fetching.
	c2 := New(Config{SpoolDir: dir})
	c2.now = func() time.Time { return now }
	c2.fetch = func(_ context.Context, _ string) ([]byte, bool) {
		t.Fatal("warm-started cache must not refetch a fresh CRL")
		return nil, false
	}
	res, ok := c2.CRLFor(context.Background(), ca.leaf)
	if !ok || len(res.Base) == 0 || !res.Reliable {
		t.Fatalf("warm-started CRLFor = (ok=%v, %d bytes, reliable=%v), want a served CRL", ok, len(res.Base), res.Reliable)
	}
}

func TestSpool_EvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1_600_000_100, 0)
	ca1 := newTestCA(t, "https://x/a.crl", "")
	ca2 := newTestCA(t, "https://x/b.crl", "")
	crl1 := ca1.makeBase(t, 1, now.Add(time.Hour))
	crl2 := ca2.makeBase(t, 1, now.Add(time.Hour))
	dir := t.TempDir()

	// Cap below two CRLs so the second insert evicts the first.
	c := New(Config{SpoolDir: dir, MaxBytes: int64(len(crl1) + len(crl2) - 1)})
	c.now = func() time.Time { return now }
	c.fetch = func(_ context.Context, u string) ([]byte, bool) {
		if u == "https://x/a.crl" {
			return crl1, true
		}
		return crl2, true
	}

	c.CRLFor(context.Background(), ca1.leaf)
	c.CRLFor(context.Background(), ca2.leaf)

	files, _ := filepath.Glob(filepath.Join(dir, "*.crl"))
	if len(files) != 1 {
		t.Errorf("spool files = %d, want 1 after LRU eviction under the size cap", len(files))
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("spool dir missing: %v", err)
	}
}
