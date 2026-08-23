package core

import (
	"testing"
	"time"
)

// stepByKey returns the diagnosis step with the given key, or fails.
func stepByKey(t *testing.T, d *Diagnosis, key string) DiagnosisStep {
	t.Helper()
	for _, s := range d.Steps {
		if s.Step == key {
			return s
		}
	}
	t.Fatalf("step %q not found in %+v", key, d.Steps)
	return DiagnosisStep{}
}

func TestBuildDiagnosis_ValidSignature(t *testing.T) {
	now := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	nb := now.Add(-24 * time.Hour)
	na := now.Add(24 * time.Hour)
	out := VerifyOutput{
		Valid: true,
		Signers: []Signer{{
			Certificate:      Certificate{NotBefore: &nb, NotAfter: &na},
			ChainComplete:    true,
			TrustAnchorFound: true,
			Revocation:       &RevocationStatus{Determinate: true},
		}},
	}
	d := buildDiagnosis(out, true, false, now)
	if !d.Valid {
		t.Fatal("expected Valid")
	}
	if stepByKey(t, d, stepSignature).Status != DiagPass {
		t.Error("signature step should pass")
	}
	if stepByKey(t, d, stepCertificateTime).Status != DiagPass {
		t.Error("certificateTime step should pass")
	}
	if stepByKey(t, d, stepChainSignatures).Status != DiagSkipped {
		t.Error("chainSignatures should be skipped when verify-chain is off")
	}
	if stepByKey(t, d, stepRevocation).Status != DiagPass {
		t.Error("revocation should pass when the check ran and found nothing")
	}
	if d.Summary != "Signature is valid." {
		t.Errorf("summary = %q", d.Summary)
	}
}

func TestBuildDiagnosis_InvalidSignatureUsesCatalog(t *testing.T) {
	out := VerifyOutput{
		Valid: false,
		Signers: []Signer{{
			Certificate:      Certificate{},
			ChainComplete:    true,
			TrustAnchorFound: true,
		}},
		LibError: &LibError{Code: "0x08F00039", Message: "The signature format does not match.", Action: "Use the same format for verify as for signing."},
	}
	d := buildDiagnosis(out, true, false, time.Now())
	sig := stepByKey(t, d, stepSignature)
	if sig.Status != DiagFail {
		t.Fatalf("signature step status = %q, want fail", sig.Status)
	}
	if sig.Summary != "The signature format does not match." {
		t.Errorf("summary from catalog = %q", sig.Summary)
	}
	if sig.Action == "" {
		t.Error("expected an action from the catalog")
	}
	if d.Summary != sig.Summary {
		t.Errorf("diagnosis summary should surface the first failing step, got %q", d.Summary)
	}
}

func TestBuildDiagnosis_NoSignature(t *testing.T) {
	d := buildDiagnosis(VerifyOutput{Valid: false}, true, false, time.Now())
	sig := stepByKey(t, d, stepSignature)
	if sig.Status != DiagFail {
		t.Fatalf("status = %q, want fail", sig.Status)
	}
	if sig.Summary != "No signature was found in the input." {
		t.Errorf("summary = %q", sig.Summary)
	}
}

func TestBuildDiagnosis_ExpiredCertTimeCheckOffIsWarn(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nb := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC) // expired vs now
	out := VerifyOutput{
		Valid:   true, // cert-time check was off, so signature math still valid
		Signers: []Signer{{Certificate: Certificate{NotBefore: &nb, NotAfter: &na}, ChainComplete: true, TrustAnchorFound: true}},
	}
	d := buildDiagnosis(out, false /*checkCertTime off*/, false, now)
	ct := stepByKey(t, d, stepCertificateTime)
	if ct.Status != DiagWarn {
		t.Errorf("expired cert with time-check off should warn, got %q", ct.Status)
	}
	// Valid overall, but the summary should carry the caveat.
	if d.Summary == "Signature is valid." {
		t.Errorf("expected a caveat in the summary, got %q", d.Summary)
	}
}

func TestBuildDiagnosis_ExpiredCertTimeCheckOnIsFail(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nb := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	out := VerifyOutput{
		Valid:   false,
		Signers: []Signer{{Certificate: Certificate{NotBefore: &nb, NotAfter: &na}, ChainComplete: true, TrustAnchorFound: true}},
	}
	d := buildDiagnosis(out, true, false, now)
	if stepByKey(t, d, stepCertificateTime).Status != DiagFail {
		t.Error("expired cert with time-check on should fail")
	}
}

func TestBuildDiagnosis_ChainAndTrustWarnings(t *testing.T) {
	now := time.Now()
	out := VerifyOutput{
		Valid:   true,
		Signers: []Signer{{Certificate: Certificate{}, ChainComplete: false, TrustAnchorFound: false}},
	}
	d := buildDiagnosis(out, false, false, now)
	if stepByKey(t, d, stepChainComplete).Status != DiagWarn {
		t.Error("incomplete chain should warn")
	}
	if stepByKey(t, d, stepTrustAnchor).Status != DiagWarn {
		t.Error("missing trust anchor should warn")
	}
	if stepByKey(t, d, stepCertificateTime).Status != DiagUnknown {
		t.Error("missing validity window should be unknown")
	}
}

func TestBuildDiagnosis_ChainSignaturesFail(t *testing.T) {
	out := VerifyOutput{
		Valid:   false,
		Signers: []Signer{{Certificate: Certificate{}, ChainComplete: true, TrustAnchorFound: true, ChainSignaturesVerified: false}},
	}
	d := buildDiagnosis(out, false, true /*chain verify on*/, time.Now())
	if stepByKey(t, d, stepChainSignatures).Status != DiagFail {
		t.Error("chain-signature check on with unverified chain should fail")
	}
}
