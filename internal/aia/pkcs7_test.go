package aia

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeP7C wraps certificate DERs into a minimal PKCS#7 certs-only SignedData.
func makeP7C(t *testing.T, certDERs ...[]byte) []byte {
	t.Helper()
	var certsContent []byte
	for _, d := range certDERs {
		certsContent = append(certsContent, d...)
	}
	dataOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})

	sd := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: dataOID},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certsContent},
		SignerInfos:      asn1.RawValue{Tag: asn1.TagSet, IsCompound: true},
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func selfSigned(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}

func TestParsePKCS7Certs(t *testing.T) {
	der := selfSigned(t, "P7C CA")
	p7 := makeP7C(t, der)

	certs := parsePKCS7Certs(p7)
	if len(certs) != 1 {
		t.Fatalf("parsed %d certs, want 1", len(certs))
	}
	if !bytes.Equal(certs[0].Raw, der) {
		t.Error("parsed cert does not match input")
	}
	// extractCert should also recognize the p7c bundle.
	if got := extractCert(p7); !bytes.Equal(got, der) {
		t.Error("extractCert did not recover the p7c certificate")
	}
	// A plain non-cert blob yields nothing.
	if parsePKCS7Certs([]byte("not asn1")) != nil {
		t.Error("expected nil for non-PKCS7 input")
	}
}

func TestFetchIssuer_PKCS7Endpoint(t *testing.T) {
	issuer := selfSigned(t, "P7C Issuer")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkcs7-mime")
		_, _ = w.Write(makeP7C(t, issuer))
	}))
	defer srv.Close()

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerCert, _ := x509.ParseCertificate(issuer)
	// Reconstruct the issuer's signing key is not needed: self-sign the leaf but
	// point its AIA at the p7c endpoint; FetchIssuer only downloads + parses.
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IssuingCertificateURL: []string{srv.URL + "/ca.p7c"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &leafKey.PublicKey, leafKey)

	got, ok := New(2*time.Second).FetchIssuer(context.Background(), leafDER)
	if !ok {
		t.Fatal("expected issuer fetch from p7c to succeed")
	}
	if !bytes.Equal(got, issuerCert.Raw) {
		t.Error("fetched p7c issuer does not match")
	}
}
