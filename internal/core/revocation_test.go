package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func issuerAndLeaf(t *testing.T, leafSerial int64) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	itmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Issuer"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	ider, _ := x509.CreateCertificate(rand.Reader, itmpl, itmpl, &ikey.PublicKey, ikey)
	issuer, _ := x509.ParseCertificate(ider)

	lkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ltmpl := &x509.Certificate{
		SerialNumber: big.NewInt(leafSerial), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	lder, _ := x509.CreateCertificate(rand.Reader, ltmpl, issuer, &lkey.PublicKey, ikey)
	leaf, _ := x509.ParseCertificate(lder)
	return issuer, ikey, leaf
}

func TestEnrichFromCRL(t *testing.T) {
	issuer, ikey, leaf := issuerAndLeaf(t, 0x99AA)
	thisUpd := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)
	nextUpd := thisUpd.Add(24 * time.Hour)
	revTime := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpd,
		NextUpdate: nextUpd,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.SerialNumber, RevocationTime: revTime, ReasonCode: 6}, // certificateHold
		},
	}, issuer, ikey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}

	var st RevocationStatus
	enrichFromCRL(&st, crlDER, leaf.Raw)
	if !st.Revoked {
		t.Fatal("expected Revoked=true")
	}
	if st.Reason != "certificateHold" {
		t.Errorf("reason = %q, want certificateHold", st.Reason)
	}
	if st.RevocationTime == nil || !st.RevocationTime.Equal(revTime) {
		t.Errorf("revocationTime = %v, want %v", st.RevocationTime, revTime)
	}
	if st.ThisUpdate == nil || st.NextUpdate == nil {
		t.Error("expected thisUpdate/nextUpdate set")
	}

	// A non-revoked serial → not marked revoked (validity window still filled).
	_, _, other := issuerAndLeaf(t, 0x1234)
	var st2 RevocationStatus
	enrichFromCRL(&st2, crlDER, other.Raw)
	if st2.Revoked {
		t.Error("unexpected revoked for a different serial")
	}
}

func TestEnrichFromOCSP(t *testing.T) {
	issuer, ikey, leaf := issuerAndLeaf(t, 0x99AA)
	produced := time.Date(2026, 5, 8, 1, 0, 0, 0, time.UTC)
	thisUpd := produced
	nextUpd := produced.Add(24 * time.Hour)
	revoked := time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC)

	respDER, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status: ocsp.Revoked, SerialNumber: leaf.SerialNumber,
		ThisUpdate: thisUpd, NextUpdate: nextUpd, ProducedAt: produced,
		RevokedAt: revoked, RevocationReason: ocsp.KeyCompromise,
	}, ikey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}

	var st RevocationStatus
	enrichFromOCSP(&st, respDER, "")
	if !st.Revoked {
		t.Fatal("expected Revoked=true")
	}
	if st.Reason != "keyCompromise" {
		t.Errorf("reason = %q, want keyCompromise", st.Reason)
	}
	if st.RevocationTime == nil || !st.RevocationTime.Equal(revoked) {
		t.Errorf("revocationTime = %v", st.RevocationTime)
	}
	if st.ThisUpdate == nil || st.NextUpdate == nil || st.ProducedAt == nil {
		t.Error("expected thisUpdate/nextUpdate/producedAt set")
	}
}

func TestEnrichFromOCSP_TextReasonFallback(t *testing.T) {
	// Unparseable response bytes → fall back to Kalkan's info text for the reason.
	var st RevocationStatus
	enrichFromOCSP(&st, []byte("not-ocsp"), "OCSP: status: revoked Reason: certificateHold")
	if st.Reason != "certificateHold" {
		t.Errorf("reason = %q, want certificateHold (text fallback)", st.Reason)
	}
}
