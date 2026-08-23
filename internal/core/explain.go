package core

import (
	"fmt"
	"time"
)

// The "why (in)valid" explainer: turn a verification into an ordered, plain-
// language diagnosis so a caller without a crypto background can see not just
// that a signature failed, but which check failed and what to do about it. It is
// a pure synthesis over the facts Verify already gathered (validity, LibError via
// the error catalog, chain/trust flags, certificate window) — no extra network
// calls. Populated on demand (VerifyInput.Explain) and carried on
// VerifyOutput.Explanation; it composes with the verification report/card.

// DiagnosisStatus is one check's outcome in a verification diagnosis.
type DiagnosisStatus string

const (
	DiagPass    DiagnosisStatus = "pass"    // the check succeeded
	DiagFail    DiagnosisStatus = "fail"    // the check failed (a reason the signature is invalid)
	DiagWarn    DiagnosisStatus = "warn"    // not fatal here, but worth attention (e.g. chain not anchored)
	DiagSkipped DiagnosisStatus = "skipped" // the check was not performed (disabled or not applicable)
	DiagUnknown DiagnosisStatus = "unknown" // the check could not be determined from available data
)

// severity orders statuses for aggregation across signers (worst wins). skipped
// is neutral and never overrides an actual outcome.
func (d DiagnosisStatus) severity() int {
	switch d {
	case DiagFail:
		return 4
	case DiagUnknown:
		return 3
	case DiagWarn:
		return 2
	case DiagPass:
		return 1
	default: // skipped
		return 0
	}
}

// DiagnosisStep is one human-readable check in the breakdown. Step is a stable
// machine key (locale-independent) for programmatic handling; Summary/Action are
// English prose for a human.
type DiagnosisStep struct {
	Step    string          `json:"step"`
	Status  DiagnosisStatus `json:"status"`
	Summary string          `json:"summary"`
	Action  string          `json:"action,omitempty"`
}

// Diagnosis is the ordered "why (in)valid" breakdown for a verification. Valid
// mirrors VerifyOutput.Valid; Steps explains it; Summary is the one-line takeaway
// (the first failing step, or a success note).
type Diagnosis struct {
	Valid   bool            `json:"valid"`
	Summary string          `json:"summary"`
	Steps   []DiagnosisStep `json:"steps"`
}

// diagnosisStep keys — stable identifiers callers can branch on.
const (
	stepSignature       = "signature"
	stepCertificateTime = "certificateTime"
	stepChainComplete   = "chainComplete"
	stepTrustAnchor     = "trustAnchor"
	stepChainSignatures = "chainSignatures"
	stepRevocation      = "revocation"
)

// buildDiagnosis synthesizes the ordered diagnosis from a completed verification.
// checkCertTime and chainVerifyOn record which checks the verify actually ran
// (they change a step's meaning: an out-of-window certificate is a failure when
// the time check was on, an informational warning when it was off). now is the
// clock the certificate window is judged against.
func buildDiagnosis(out VerifyOutput, checkCertTime, chainVerifyOn bool, now time.Time) *Diagnosis {
	d := &Diagnosis{Valid: out.Valid}
	d.Steps = append(d.Steps,
		signatureStep(out),
		certificateTimeStep(out.Signers, checkCertTime, now),
		chainCompleteStep(out.Signers),
		trustAnchorStep(out.Signers),
		chainSignaturesStep(out.Signers, chainVerifyOn),
		revocationStep(out),
	)
	d.Summary = diagnosisSummary(d)
	return d
}

// signatureStep reports whether a signature was present and cryptographically
// verified, drawing the remedy from the error catalog when it failed.
func signatureStep(out VerifyOutput) DiagnosisStep {
	if out.Valid {
		return DiagnosisStep{Step: stepSignature, Status: DiagPass,
			Summary: "The signature is cryptographically valid."}
	}
	if len(out.Signers) == 0 && out.LibError == nil {
		return DiagnosisStep{Step: stepSignature, Status: DiagFail,
			Summary: "No signature was found in the input.",
			Action:  "Check that the payload is a signed container in the declared format (cms/xml/wsse)."}
	}
	step := DiagnosisStep{Step: stepSignature, Status: DiagFail,
		Summary: "The signature did not verify cryptographically."}
	if le := out.LibError; le != nil {
		if le.Message != "" {
			step.Summary = le.Message
		}
		step.Action = le.Action
	}
	if step.Action == "" {
		step.Action = "The content may have been altered, or the wrong original data / format was supplied."
	}
	return step
}

// certificateTimeStep checks each signer certificate's validity window against
// now. When the library's time check was off, an out-of-window certificate did
// not cause the failure, so it is surfaced as a warning rather than a failure.
func certificateTimeStep(signers []Signer, checkCertTime bool, now time.Time) DiagnosisStep {
	step := DiagnosisStep{Step: stepCertificateTime, Status: DiagPass,
		Summary: "Every signer certificate was within its validity period."}
	if len(signers) == 0 {
		step.Status = DiagSkipped
		step.Summary = "No signer certificate to check."
		return step
	}
	failStatus := DiagWarn
	if checkCertTime {
		failStatus = DiagFail
	}
	for i := range signers {
		c := signers[i].Certificate
		if c.NotBefore == nil || c.NotAfter == nil {
			step.merge(DiagUnknown, "A signer certificate's validity window is unavailable.",
				"Parse the certificate (cert/info) to inspect notBefore/notAfter.")
			continue
		}
		if now.Before(*c.NotBefore) {
			step.merge(failStatus, "A signer certificate was not yet valid at verification time.",
				"Verify against the signing time, or confirm the certificate's notBefore.")
		} else if now.After(*c.NotAfter) {
			step.merge(failStatus, "A signer certificate had expired at verification time.",
				"Use point-in-time verification (/verify/at) to check validity as of the signing time.")
		}
	}
	return step
}

// chainCompleteStep reports whether every signer's chain reached a self-signed
// root. An incomplete chain is a warning, not a hard failure — the signature can
// still be cryptographically valid.
func chainCompleteStep(signers []Signer) DiagnosisStep {
	step := DiagnosisStep{Step: stepChainComplete, Status: DiagPass,
		Summary: "The certificate chain was built to a self-signed root."}
	if len(signers) == 0 {
		step.Status = DiagSkipped
		step.Summary = "No signer to build a chain for."
		return step
	}
	for i := range signers {
		if !signers[i].ChainComplete {
			step.merge(DiagWarn, "The certificate chain is incomplete (no self-signed root reached).",
				"Supply the issuing CA(s) via trustedCerts, or enable AIA fetch / the RK CA registry.")
		}
	}
	return step
}

// trustAnchorStep reports whether the chain was anchored to a configured trusted
// root. Absence is a warning: cryptographic validity does not imply the signer is
// trusted.
func trustAnchorStep(signers []Signer) DiagnosisStep {
	step := DiagnosisStep{Step: stepTrustAnchor, Status: DiagPass,
		Summary: "The chain is anchored to a configured trusted root."}
	if len(signers) == 0 {
		step.Status = DiagSkipped
		step.Summary = "No signer to anchor."
		return step
	}
	for i := range signers {
		if !signers[i].TrustAnchorFound {
			step.merge(DiagWarn, "The chain is not anchored to any configured trust anchor.",
				"Load the RK CA trust store (trust.use-rk-registry or trust.ca-dir) so the signer can be trusted.")
		}
	}
	return step
}

// chainSignaturesStep reports the cryptographic chain-signature check (GOST-
// capable, via Kalkan). It is only meaningful when chain verification was
// enabled; otherwise it is skipped.
func chainSignaturesStep(signers []Signer, chainVerifyOn bool) DiagnosisStep {
	if !chainVerifyOn {
		return DiagnosisStep{Step: stepChainSignatures, Status: DiagSkipped,
			Summary: "Chain-signature verification was not enabled.",
			Action:  "Enable trust.verify-chain to cryptographically validate the chain (incl. GOST)."}
	}
	step := DiagnosisStep{Step: stepChainSignatures, Status: DiagPass,
		Summary: "The chain signatures were cryptographically verified."}
	if len(signers) == 0 {
		step.Status = DiagSkipped
		step.Summary = "No signer chain to verify."
		return step
	}
	for i := range signers {
		if !signers[i].ChainSignaturesVerified {
			step.merge(DiagFail, "A signer chain did not cryptographically validate against the anchors.",
				"Confirm the correct issuing CAs and trust anchors are loaded.")
		}
	}
	return step
}

// revocationStep reports the revocation outcome per signer. An unestablished
// status is unknown rather than skipped: a verdict of "valid" that quietly left
// out revocation is the one way a repudiated signature gets reported as good, so
// not knowing has to make the overall verdict indeterminate.
//
// The exception is a signature that did not verify at all — revocation is never
// reached there, and the verdict is already invalid on the signature step.
func revocationStep(out VerifyOutput) DiagnosisStep {
	checked := 0
	step := DiagnosisStep{Step: stepRevocation, Status: DiagPass,
		Summary: "No signer certificate has been revoked."}
	for _, signer := range out.Signers {
		switch {
		case signer.Revocation == nil:
			step.merge(DiagUnknown, "Revocation status was not checked as part of verification.",
				"Leave revocationCheck on, or check separately via /cert/validate (now) or /verify/at (as of a past instant).")
		case !signer.Revocation.Determinate:
			step.merge(DiagUnknown, "Revocation status could not be established (the responder did not answer).",
				"Retry when the responder is reachable; do not read an unanswered check as \"not revoked\".")
		case signer.Revocation.Revoked:
			step.merge(DiagFail, "A signer certificate has been revoked.",
				"Reject the signature: the key it was made with has been repudiated.")
		default:
			checked++
		}
	}
	if !out.Valid && checked == 0 && step.Status == DiagUnknown {
		// Not reached rather than unanswered — the signature failed first.
		return DiagnosisStep{Step: stepRevocation, Status: DiagSkipped,
			Summary: "Revocation was not checked: the signature did not verify.",
			Action:  "Fix the signature first; revocation is only meaningful for a signature that verifies."}
	}
	if len(out.Signers) == 0 {
		return DiagnosisStep{Step: stepRevocation, Status: DiagSkipped,
			Summary: "No signer to check revocation for."}
	}
	return step
}

// merge lowers a step toward a worse status, keeping the most severe summary and
// action so the aggregated step reflects the biggest problem across signers.
func (s *DiagnosisStep) merge(status DiagnosisStatus, summary, action string) {
	if status.severity() > s.Status.severity() {
		s.Status = status
		s.Summary = summary
		s.Action = action
	}
}

// diagnosisSummary produces the one-line takeaway: the first failing step's
// summary, else the first warning's, else a success/neutral note.
func diagnosisSummary(d *Diagnosis) string {
	if d.Valid {
		if warn := firstStepOf(d.Steps, DiagWarn); warn != nil {
			return fmt.Sprintf("Signature is valid, with a caveat: %s", warn.Summary)
		}
		return "Signature is valid."
	}
	if fail := firstStepOf(d.Steps, DiagFail); fail != nil {
		return fail.Summary
	}
	return "Signature is not valid."
}

// firstStepOf returns the first step with the given status, or nil.
func firstStepOf(steps []DiagnosisStep, status DiagnosisStatus) *DiagnosisStep {
	for i := range steps {
		if steps[i].Status == status {
			return &steps[i]
		}
	}
	return nil
}
