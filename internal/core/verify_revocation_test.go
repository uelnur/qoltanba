package core

import (
	"context"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// These pin the property the service exists to guarantee: it never reports a
// signature as good without having established that the signer was not revoked.
// Before this, verify skipped revocation entirely and the report still read
// "valid" — a consumer who did everything right got a clean verdict on a
// repudiated signature.

// revocationFixture builds a service whose fake driver answers the revocation
// check with the given status.
func revocationFixture(t *testing.T, status provider.CertStatus) (*fakeProvider, *Service) {
	t.Helper()
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{
		verifyResult: provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}},
		props: fields(map[string]string{
			"SUBJECT_COMMONNAME": "Leaf",
			"NOTBEFORE":          "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":           "01.01.2030 00:00:00 +00:00",
		}),
		validateResult: provider.ValidateResult{Status: status},
	}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))
	return prov, svc
}

func TestVerify_RevokedSignerIsNotValid(t *testing.T) {
	_, svc := revocationFixture(t, provider.StatusRevoked)

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("s"), Report: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Valid {
		t.Error("a signature by a revoked certificate must not be reported valid")
	}
	if out.Signers[0].Revocation == nil || !out.Signers[0].Revocation.Revoked {
		t.Errorf("the revocation status must reach the caller: %+v", out.Signers[0].Revocation)
	}
	if out.Report.Verdict != VerdictInvalid {
		t.Errorf("verdict = %q, want invalid", out.Report.Verdict)
	}
}

// TestVerify_UnreachableResponderIsIndeterminate covers the failure shape that
// makes this dangerous: the library reports an unanswered check as a soft error
// with Revoked=false, which is byte-identical to a clean answer.
func TestVerify_UnreachableResponderIsIndeterminate(t *testing.T) {
	_, svc := revocationFixture(t, provider.StatusUnknown)

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("s"), Report: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Signers[0].Revocation.Determinate {
		t.Error("an unanswered check must not be recorded as determinate")
	}
	if out.Report.Verdict != VerdictIndeterminate {
		t.Errorf("verdict = %q, want indeterminate — not knowing is not the same as not revoked", out.Report.Verdict)
	}
}

// TestVerify_SkippedRevocationIsNotValid pins the honest verdict for a caller
// who turned the check off: the question was left open, so the answer cannot be
// "valid".
func TestVerify_SkippedRevocationIsNotValid(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusGood)

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("s"), Report: true, RevocationCheck: revocationOff(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if prov.lastValidate != nil {
		t.Error("the driver must not be asked when the caller turned the check off")
	}
	if !out.Valid {
		t.Error("skipping revocation does not make the signature itself invalid")
	}
	if out.Report.Verdict != VerdictIndeterminate {
		t.Errorf("verdict = %q, want indeterminate", out.Report.Verdict)
	}
}

func TestVerify_RevocationCheckedByDefault(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusGood)

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("s"), Report: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if prov.lastValidate == nil {
		t.Fatal("revocation must be checked without the caller asking for it")
	}
	if !out.Signers[0].Revocation.Determinate || out.Signers[0].Revocation.Revoked {
		t.Errorf("status = %+v, want a determined, not-revoked answer", out.Signers[0].Revocation)
	}
	if out.Report.Verdict != VerdictValid {
		t.Errorf("verdict = %q, want valid", out.Report.Verdict)
	}
}

// TestVerify_RevocationSkippedForBrokenSignature keeps the check off the network
// when there is nothing to check: an invalid signature is already invalid.
func TestVerify_RevocationSkippedForBrokenSignature(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusGood)
	prov.verifyResult = provider.VerifyResult{Valid: false}

	if _, err := svc.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if prov.lastValidate != nil {
		t.Error("no responder call is warranted for a signature that did not verify")
	}
}
