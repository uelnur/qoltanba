package aia

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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchIssuer_DownloadsDER(t *testing.T) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Issuer"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)

	// Serve the issuer as raw DER (the common .cer case) and PEM at two paths.
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.cer", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(issuerDER) })
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, _ *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerCert, _ := x509.ParseCertificate(issuerDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IssuingCertificateURL: []string{srv.URL + "/ca.cer"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)

	f := New(2 * time.Second)
	got, ok := f.FetchIssuer(context.Background(), leafDER)
	if !ok {
		t.Fatal("expected issuer fetch to succeed")
	}
	if !bytes.Equal(got, issuerDER) {
		t.Error("fetched DER does not match the issuer")
	}

	// Second call is served from cache (server could be down); still succeeds.
	srv.Close()
	if _, ok := f.FetchIssuer(context.Background(), leafDER); !ok {
		t.Error("expected cached issuer on second call")
	}
}

func TestFetchIssuer_NoAIA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NoAIA"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if _, ok := New(time.Second).FetchIssuer(context.Background(), der); ok {
		t.Error("expected miss when the cert has no CA Issuers URL")
	}
}
