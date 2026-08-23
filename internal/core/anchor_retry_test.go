package core

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// fakeFetcher returns a fixed issuer DER for any certificate (one leaf per test).
type fakeFetcher struct{ issuerDER []byte }

func (f fakeFetcher) FetchIssuer(_ context.Context, _ []byte) ([]byte, bool) {
	return f.issuerDER, len(f.issuerDER) > 0
}

// anchorRetryProvider makes VerifyCMS fail like a missing-CA anchor until the
// issuing cert is supplied as a trusted cert, then succeed.
func anchorRetryFunc(leafPEM []byte) func(provider.VerifyRequest) (provider.VerifyResult, error) {
	return func(req provider.VerifyRequest) (provider.VerifyResult, error) {
		if len(req.TrustedCerts) == 0 {
			return provider.VerifyResult{Signers: [][]byte{leafPEM}}, provider.ErrCertTimeInvalid
		}
		return provider.VerifyResult{Valid: true, Signers: [][]byte{leafPEM}}, nil
	}
}

func TestVerify_RetriesWithAIADiscoveredAnchor(t *testing.T) {
	issuer, _, leaf := issuerAndLeaf(t, 0x1234) // issuer signs leaf and is self-signed
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	f := &fakeProvider{
		props:      fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		verifyFunc: anchorRetryFunc(leafPEM),
	}
	s := New(f, WithIssuerFetcher(fakeFetcher{issuerDER: issuer.Raw}))

	out, err := s.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), CheckCertTime: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected Valid after anchor retry (verifyCalls=%d)", f.verifyCalls)
	}
	if f.verifyCalls != 2 {
		t.Errorf("verifyCalls = %d, want 2 (one retry)", f.verifyCalls)
	}
}

func TestVerify_NoRetryWithoutFetcher(t *testing.T) {
	_, _, leaf := issuerAndLeaf(t, 0x1234)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	f := &fakeProvider{
		props:      fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		verifyFunc: anchorRetryFunc(leafPEM),
	}
	s := New(f) // no issuer fetcher → no retry

	out, err := s.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), CheckCertTime: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Valid {
		t.Error("without a fetcher there is no retry; expected Valid=false")
	}
	if f.verifyCalls != 1 {
		t.Errorf("verifyCalls = %d, want 1 (no retry)", f.verifyCalls)
	}
	if out.LibError == nil {
		t.Error("expected the soft failure surfaced as LibError")
	}
}

// certTimeQuirkFunc mimics Kalkan's GOST-2015 VerifyData quirk: the time-checked
// verify rejects with 0x08F00042, but the signature math (cert-time off) is valid.
func certTimeQuirkFunc(leafPEM []byte) func(provider.VerifyRequest) (provider.VerifyResult, error) {
	return func(req provider.VerifyRequest) (provider.VerifyResult, error) {
		if req.CheckCertTime {
			return provider.VerifyResult{Signers: [][]byte{leafPEM}}, provider.ErrCertTimeInvalid
		}
		return provider.VerifyResult{Valid: true, Signers: [][]byte{leafPEM}}, nil
	}
}

func TestVerify_CertTimeAnchorOverride(t *testing.T) {
	issuer, _, leaf := issuerAndLeaf(t, 0x55)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	f := &fakeProvider{
		props: fields(map[string]string{
			"SUBJECT_COMMONNAME": "Leaf",
			"NOTBEFORE":          "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":           "01.01.2030 00:00:00 +00:00",
		}),
		validateResult: provider.ValidateResult{RawCode: 0}, // chain verify (KC_USE_NOTHING) succeeds
		verifyFunc:     certTimeQuirkFunc(leafPEM),
	}
	s := New(f, WithChainVerification(true), WithClock(func() time.Time { return now }))

	out, err := s.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), CheckCertTime: true,
		TrustedCerts: []TrustedCert{{Cert: issuerPEM}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected composite override → valid=true; signer=%+v", out.Signers[0])
	}
	if out.LibError != nil {
		t.Errorf("libError should be cleared on override, got %v", out.LibError)
	}
	if !out.Signers[0].Valid {
		t.Error("signer.Valid should be true after override")
	}
	var hasWarn bool
	for _, wn := range out.Warnings {
		if wn.Field == "verify" {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Error("expected an override warning explaining the composite verdict")
	}
}

func TestVerify_NoOverrideWithoutChainVerification(t *testing.T) {
	issuer, _, leaf := issuerAndLeaf(t, 0x55)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})
	f := &fakeProvider{
		props:          fields(map[string]string{"NOTBEFORE": "01.01.2021 00:00:00 +00:00", "NOTAFTER": "01.01.2030 00:00:00 +00:00"}),
		validateResult: provider.ValidateResult{RawCode: 0},
		verifyFunc:     certTimeQuirkFunc(leafPEM),
	}
	// Chain verification OFF → no chainSignaturesVerified → no override.
	s := New(f, WithClock(func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) }))
	out, err := s.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), CheckCertTime: true,
		TrustedCerts: []TrustedCert{{Cert: issuerPEM}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Valid {
		t.Error("without chain verification there must be no override")
	}
	if out.LibError == nil {
		t.Error("expected the soft failure surfaced as LibError")
	}
}

func TestVerify_NoRetryWhenCheckCertTimeOff(t *testing.T) {
	issuer, _, leaf := issuerAndLeaf(t, 0x1234)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	f := &fakeProvider{
		props:      fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		verifyFunc: anchorRetryFunc(leafPEM),
	}
	s := New(f, WithIssuerFetcher(fakeFetcher{issuerDER: issuer.Raw}))

	// CheckCertTime off: the library does not anchor, so there is nothing to retry.
	out, _ := s.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), CheckCertTime: false,
	})
	if f.verifyCalls != 1 {
		t.Errorf("verifyCalls = %d, want 1 (no retry when cert-time off)", f.verifyCalls)
	}
	_ = out
}
