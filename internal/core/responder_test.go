package core

import (
	"context"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// A revocation check with no responder named used to fall through to the
// library's built-in default — the production responder, which knows nothing
// about a certificate from another CA. The check then failed in a way that read
// as "not revoked" to anyone not inspecting determinate. The responder the
// issuer published in the certificate is the one that can answer for it.

func TestValidate_UsesTheResponderFromTheCertificate(t *testing.T) {
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusGood}}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}))

	out, err := svc.Validate(context.Background(), ValidateInput{
		Cert: leaf.pem, Format: EncodingPEM, Method: MethodOCSP,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if prov.lastValidate == nil {
		t.Fatal("the driver was never asked")
	}
	if got := prov.lastValidate.Path; got != "http://ocsp.test.example/" {
		t.Errorf("responder = %q, want the one published in the certificate", got)
	}
	if !out.Status.Determinate {
		t.Error("a responder that answered yields a determined status")
	}
}

func TestValidate_ExplicitResponderWins(t *testing.T) {
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusGood}}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}))

	if _, err := svc.Validate(context.Background(), ValidateInput{
		Cert: leaf.pem, Format: EncodingPEM, Method: MethodOCSP,
		ResponderURL: "http://chosen.example/",
	}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := prov.lastValidate.Path; got != "http://chosen.example/" {
		t.Errorf("responder = %q, want the caller's", got)
	}
}

// TestValidate_NoResponderIsUndetermined pins the decision for a certificate
// that publishes none: guessing is what made this silent, so the status is left
// undetermined instead of being asked of whatever responder happens to answer.
func TestValidate_NoResponderIsUndetermined(t *testing.T) {
	// A CA certificate from the test builder carries no AIA.
	root := makeCert(t, "Root", nil, true)
	prov := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusGood}}
	svc := New(prov)

	out, err := svc.Validate(context.Background(), ValidateInput{
		Cert: root.pem, Format: EncodingPEM, Method: MethodOCSP,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if prov.lastValidate != nil {
		t.Error("no responder is known, so the driver must not be asked at all")
	}
	if out.Status.Determinate || out.Status.Revoked {
		t.Errorf("status = %+v, want undetermined and not revoked", out.Status)
	}
	if len(out.Warnings) == 0 {
		t.Error("the caller must be told why the status is undetermined")
	}
}

// TestVerify_ValidWithoutSignersIsRefused covers the shape the consumer hit on a
// DER container: the library reported the maths held while the signer walk came
// back empty, and a verdict naming nobody was reported as valid.
func TestVerify_ValidWithoutSignersIsRefused(t *testing.T) {
	prov := &fakeProvider{verifyResult: provider.VerifyResult{Valid: true}}
	svc := New(prov)

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("sig"), Report: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Valid {
		t.Error("a verdict with no signer must not be reported valid")
	}
	if out.Report.Verdict != VerdictInvalid {
		t.Errorf("verdict = %q, want invalid", out.Report.Verdict)
	}
	if len(out.Warnings) == 0 {
		t.Error("the refusal must say why")
	}
}

// TestCertInfo_BuildsChainWhenAsked covers a flag that was declared in the
// contract, documented, exposed over gRPC — and never read, so every caller that
// asked for the chain got an empty one back.
func TestCertInfo_BuildsChainWhenAsked(t *testing.T) {
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{props: fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"})}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}))

	out, err := svc.CertInfo(context.Background(), CertInfoInput{
		Cert: leaf.pem, Format: EncodingPEM, BuildChain: true,
	})
	if err != nil {
		t.Fatalf("CertInfo: %v", err)
	}
	if len(out.Chain) != 2 {
		t.Fatalf("chain = %d nodes, want the leaf and its issuer: %+v", len(out.Chain), out.Warnings)
	}

	// Without the flag the chain stays absent — the work is not done unasked.
	plain, err := svc.CertInfo(context.Background(), CertInfoInput{Cert: leaf.pem, Format: EncodingPEM})
	if err != nil {
		t.Fatalf("CertInfo: %v", err)
	}
	if len(plain.Chain) != 0 {
		t.Errorf("chain = %d nodes without buildChain, want none", len(plain.Chain))
	}
}
