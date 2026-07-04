package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

func newTestService(f *fakeProvider, opts ...Option) *Service {
	base := []Option{
		WithKeySource(staticKeySource{ref: provider.KeyRef{Path: "/k.p12"}}),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
	}
	return New(f, append(base, opts...)...)
}

func TestSign_DispatchByFormat(t *testing.T) {
	f := &fakeProvider{signResult: provider.SignResult{Signature: []byte("SIG")}}
	s := newTestService(f)

	out, err := s.Sign(context.Background(), SignInput{
		Format: FormatCMS, Data: []byte("data"),
		Key: KeySpec{Path: &PathKey{Path: "/k.p12"}}, Detached: true,
	})
	if err != nil {
		t.Fatalf("Sign CMS: %v", err)
	}
	if string(out.Signature) != "SIG" || out.Format != FormatCMS {
		t.Fatalf("unexpected output %+v", out)
	}
	if f.lastSignCMS == nil || !f.lastSignCMS.Detached {
		t.Fatal("SignCMS not called with Detached")
	}
	// NoCheckCertTime defaults false → driver CheckCertTime true (safe default).
	if !f.lastSignCMS.CheckCertTime {
		t.Error("expected CheckCertTime=true by default")
	}

	if _, err := s.Sign(context.Background(), SignInput{Format: FormatXML, Key: KeySpec{Path: &PathKey{}}}); err != nil {
		t.Fatalf("Sign XML: %v", err)
	}
	if f.lastSignXML == nil {
		t.Error("SignXML not dispatched")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestSign_TimestampTriState(t *testing.T) {
	f := &fakeProvider{signResult: provider.SignResult{Signature: []byte("SIG")}}
	key := KeySpec{Path: &PathKey{Path: "/k.p12"}}

	// Default ON, request unspecified → driver gets true, cadesLevel T.
	on := New(f, WithKeySource(staticKeySource{}), WithDefaultTimestamp(true))
	out, _ := on.Sign(context.Background(), SignInput{Format: FormatCMS, Key: key})
	if !f.lastSignCMS.WithTimestamp {
		t.Error("default-on + unspecified → expected timestamp true")
	}
	if out.CAdESLevel != "T" {
		t.Errorf("cadesLevel = %q, want T", out.CAdESLevel)
	}

	// Request explicitly false overrides the ON default.
	out, _ = on.Sign(context.Background(), SignInput{Format: FormatCMS, Key: key, WithTimestamp: boolPtr(false)})
	if f.lastSignCMS.WithTimestamp {
		t.Error("explicit false must override default-on")
	}
	if out.CAdESLevel != "BES" {
		t.Errorf("cadesLevel = %q, want BES", out.CAdESLevel)
	}

	// Default OFF, request true.
	off := New(f, WithKeySource(staticKeySource{}))
	off.Sign(context.Background(), SignInput{Format: FormatCMS, Key: key, WithTimestamp: boolPtr(true)})
	if !f.lastSignCMS.WithTimestamp {
		t.Error("explicit true must enable timestamp when default is off")
	}
}

func TestSign_VerifyOnlyRejected(t *testing.T) {
	f := &fakeProvider{}
	s := newTestService(f, WithVerifyOnly(true))
	_, err := s.Sign(context.Background(), SignInput{Format: FormatCMS, Key: KeySpec{Path: &PathKey{}}})
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindInvalid {
		t.Fatalf("want KindInvalid, got %v", err)
	}
}

func TestSign_CoSignNonCMSRejected(t *testing.T) {
	s := newTestService(&fakeProvider{})
	_, err := s.Sign(context.Background(), SignInput{
		Format: FormatXML, ExistingSignature: []byte("x"), Key: KeySpec{Path: &PathKey{}},
	})
	if err == nil {
		t.Fatal("expected co-sign rejection for XML")
	}
}

func TestVerify_SoftFailureIsNotError(t *testing.T) {
	f := &fakeProvider{
		verifyResult: provider.VerifyResult{Valid: false},
		verifyErr:    provider.NewNativeError("VerifyCMS", 0x08F0001C, "bad sig", provider.ErrSignatureInvalid),
	}
	s := newTestService(f)
	out, err := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if err != nil {
		t.Fatalf("soft failure must not be a transport error: %v", err)
	}
	if out.Valid {
		t.Error("expected Valid=false")
	}
	if out.LibError == nil || out.LibError.Code != "0x08F0001C" {
		t.Errorf("LibError = %+v, want code 0x08F0001C", out.LibError)
	}
}

func TestVerify_HardFailureIsError(t *testing.T) {
	f := &fakeProvider{verifyErr: provider.ErrUnsupported}
	s := newTestService(f)
	_, err := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindUnsupported {
		t.Fatalf("want KindUnsupported, got %v", err)
	}
}

func TestVerify_ExtractsSigners(t *testing.T) {
	f := &fakeProvider{
		verifyResult: provider.VerifyResult{
			Valid:   true,
			Info:    "ok",
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		props: fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123"}),
	}
	s := newTestService(f)
	out, err := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(out.Signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(out.Signers))
	}
	if out.Signers[0].Certificate.Subject.IIN != "900130300123" {
		t.Errorf("signer IIN = %q", out.Signers[0].Certificate.Subject.IIN)
	}
	if out.Signers[0].CAdESLevel != "BES" {
		t.Errorf("cadesLevel = %q, want BES", out.Signers[0].CAdESLevel)
	}
}

func TestCertInfo_FromInputCert(t *testing.T) {
	f := &fakeProvider{props: fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN900130300123",
	})}
	s := newTestService(f)
	out, err := s.CertInfo(context.Background(), CertInfoInput{Cert: []byte("PEMDATA"), Format: EncodingPEM})
	if err != nil {
		t.Fatalf("CertInfo: %v", err)
	}
	if out.Certificate.Subject.IIN != "900130300123" {
		t.Errorf("IIN = %q", out.Certificate.Subject.IIN)
	}
}

type staticTrust struct{ anchors []TrustedCert }

func (s staticTrust) Anchors() []TrustedCert { return s.anchors }

func TestVerify_ChainSignaturesVerified(t *testing.T) {
	root := makeCert(t, "Root", nil, true)
	inter := makeCert(t, "Inter", &root, true)
	leaf := makeCert(t, "Leaf", &inter, false)

	f := &fakeProvider{
		verifyResult:   provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}},
		props:          fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		validateResult: provider.ValidateResult{RawCode: 0}, // chain valid
	}
	trust := staticTrust{[]TrustedCert{{Cert: root.pem}, {Cert: inter.pem, Intermediate: true}}}
	s := New(f, WithTrustStore(trust), WithChainVerification(true),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))

	out, err := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.Signers[0].ChainSignaturesVerified {
		t.Fatal("expected ChainSignaturesVerified=true when Kalkan validates the chain")
	}
	// The driver was asked for a chain-only (no revocation) validation.
	if f.lastValidate == nil || f.lastValidate.Method != provider.ValidateNone {
		t.Errorf("expected ValidateNone, got %+v", f.lastValidate)
	}

	// A chain error from the driver → flag false, not a Verify failure.
	f.validateErr = provider.NewNativeError("ValidateCert", 0x08F0000E, "chain", provider.ErrChainInvalid)
	out2, err := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if err != nil {
		t.Fatalf("Verify (chain-fail): %v", err)
	}
	if out2.Signers[0].ChainSignaturesVerified {
		t.Error("expected ChainSignaturesVerified=false on chain error")
	}
}

func TestVerify_ChainVerificationDisabled(t *testing.T) {
	f := &fakeProvider{
		verifyResult:   provider.VerifyResult{Valid: true, Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")}},
		props:          fields(map[string]string{"SUBJECT_COMMONNAME": "X"}),
		validateResult: provider.ValidateResult{RawCode: 0},
	}
	s := newTestService(f) // chain verification not enabled
	out, _ := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if out.Signers[0].ChainSignaturesVerified {
		t.Error("flag must stay false when chain verification is disabled")
	}
	if f.lastValidate != nil {
		t.Error("ValidateCert must not be called when chain verification is disabled")
	}
}

func TestValidate_RevokedMapping(t *testing.T) {
	f := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusRevoked, Info: "revoked"}}
	s := newTestService(f)
	out, err := s.Validate(context.Background(), ValidateInput{Cert: []byte("c"), Method: MethodOCSP})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !out.Status.Revoked {
		t.Error("expected Revoked=true")
	}
	if out.Status.CheckedAt == nil {
		t.Error("expected CheckedAt set")
	}
	if f.lastValidate == nil || f.lastValidate.CheckTime.IsZero() {
		t.Error("expected CheckTime defaulted to clock")
	}
}
