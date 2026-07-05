package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

func TestValidate_SoftFailFallsBackToOCSP(t *testing.T) {
	f := &fakeProvider{validateResult: provider.ValidateResult{RawCode: 0}}
	fc := &fakeCRLSource{ok: true, reliable: false, reason: "stale-base"} // unreliable CRL
	s := newTestService(f, WithCRLSource(fc))                             // default policy is soft

	out, err := s.Validate(context.Background(), ValidateInput{
		Cert: []byte("cert"), Format: EncodingDER, Method: MethodCRL,
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if f.lastValidate == nil || f.lastValidate.Method != provider.ValidateOCSP {
		t.Fatalf("provider method = %v, want OCSP fallback", f.lastValidate)
	}
	if out.Status.Method != MethodOCSP {
		t.Errorf("status method = %q, want ocsp after soft fallback", out.Status.Method)
	}
	if !hasWarning(out.Warnings, "crl", "fallback-to-ocsp:stale-base") {
		t.Errorf("warnings = %+v, want a crl fallback-to-ocsp:stale-base warning", out.Warnings)
	}
}

func TestValidate_HardFailReturnsInvalid(t *testing.T) {
	f := &fakeProvider{validateResult: provider.ValidateResult{RawCode: 0}}
	fc := &fakeCRLSource{ok: true, reliable: false, reason: "delta-inconsistent"}
	s := newTestService(f, WithCRLSource(fc), WithCRLFailPolicy(CRLFailHard))

	_, err := s.Validate(context.Background(), ValidateInput{
		Cert: []byte("cert"), Format: EncodingDER, Method: MethodCRL,
	})
	if err == nil {
		t.Fatal("hard fail policy must return an error for an unreliable CRL")
	}
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindInvalid {
		t.Errorf("error = %v, want a KindInvalid domain error", err)
	}
	if f.lastValidate != nil {
		t.Error("provider must not be consulted when the CRL fails closed")
	}
}

func TestValidate_ReliableCRLOverlaysDeltaRevocation(t *testing.T) {
	// The base CRL does not list the leaf; a consistent delta does. The library
	// verdict on the base is "good", so the domain must overlay the delta's
	// revocation to report revoked.
	leafDER, baseCRL, deltaCRL := certWithBaseAndDelta(t)
	f := &fakeProvider{validateResult: provider.ValidateResult{RawCode: 0, Status: provider.StatusGood}}
	fc := &fakeCRLSource{der: baseCRL, delta: deltaCRL, reliable: true}
	s := newTestService(f, WithCRLSource(fc))

	out, err := s.Validate(context.Background(), ValidateInput{
		Cert: leafDER, Format: EncodingDER, Method: MethodCRL,
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !out.Status.Revoked {
		t.Error("delta-only revocation was not overlaid: status.Revoked = false")
	}
	if out.Status.RevocationTime == nil {
		t.Error("revocationTime not populated from the delta CRL")
	}
}

// certWithBaseAndDelta builds a leaf and two CRLs from one CA: a base CRL that
// does not revoke the leaf and a delta CRL that does.
func certWithBaseAndDelta(t *testing.T) (leafDER, baseCRL, deltaCRL []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial := big.NewInt(42)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	leafDER, _ = x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)

	next := time.Unix(1_900_000_000, 0)
	baseTmpl := &x509.RevocationList{Number: big.NewInt(10), ThisUpdate: time.Unix(1_600_000_000, 0), NextUpdate: next}
	baseCRL, _ = x509.CreateRevocationList(rand.Reader, baseTmpl, ca, caKey)

	deltaTmpl := &x509.RevocationList{
		Number: big.NewInt(11), ThisUpdate: time.Unix(1_600_000_000, 0), NextUpdate: next,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leafSerial, RevocationTime: time.Unix(1_650_000_000, 0)},
		},
	}
	deltaCRL, _ = x509.CreateRevocationList(rand.Reader, deltaTmpl, ca, caKey)
	return leafDER, baseCRL, deltaCRL
}

func hasWarning(ws []Warning, field, reason string) bool {
	for _, w := range ws {
		if w.Field == field && w.Reason == reason {
			return true
		}
	}
	return false
}
