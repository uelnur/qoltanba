package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ReportVerdict is the one-word outcome a person reads first. It is deliberately
// three-valued: a check that could not be performed (an unreachable responder,
// an unverifiable chain) is not the same as a signature that failed, and
// collapsing the two either raises false alarms or hides real doubt.
type ReportVerdict string

const (
	VerdictValid         ReportVerdict = "valid"
	VerdictInvalid       ReportVerdict = "invalid"
	VerdictIndeterminate ReportVerdict = "indeterminate"
)

// VerificationReport is the human-facing verification card: who signed, when,
// with what, and what the service could establish about it. It answers "show me
// this signature" without the caller having to interpret flags, and it is the
// payload a verification receipt attests to.
//
// It is a synthesis over a completed verification — no extra network calls, no
// extra crypto — so it is available on every transport and inside batches.
type VerificationReport struct {
	Verdict   ReportVerdict  `json:"verdict"`
	Summary   string         `json:"summary"`
	CheckedAt time.Time      `json:"checkedAt"`
	Document  ReportDocument `json:"document"`
	Signers   []ReportSigner `json:"signers,omitempty"`
	// Steps is the same ordered diagnosis the explain flag returns, carried here
	// so the card stands on its own.
	Steps    []DiagnosisStep `json:"steps,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
}

// ReportDocument identifies what was checked. The digests bind a report (and any
// receipt built from it) to exact bytes: without them a receipt would attest to
// "some document", which is worthless as evidence.
type ReportDocument struct {
	Format          SignatureFormat `json:"format,omitempty"`
	Detached        bool            `json:"detached"`
	SignatureSHA256 string          `json:"signatureSha256,omitempty"`
	ContentSHA256   string          `json:"contentSha256,omitempty"`
	ContentBytes    int             `json:"contentBytes,omitempty"`
}

// ReportSigner is one signer as a person would describe them, with the raw
// certificate detail kept to what identifies it.
type ReportSigner struct {
	Name         string     `json:"name,omitempty"`
	IIN          string     `json:"iin,omitempty"`
	BIN          string     `json:"bin,omitempty"`
	Organization string     `json:"organization,omitempty"`
	OwnerType    string     `json:"ownerType,omitempty"`
	Roles        []string   `json:"roles,omitempty"`
	Valid        bool       `json:"valid"`
	SignedAt     *time.Time `json:"signedAt,omitempty"`
	// SignedAtSource says where SignedAt came from: a TSA timestamp is evidence,
	// a signing-time attribute is the signer's own claim.
	SignedAtSource     string `json:"signedAtSource,omitempty"` // timestamp | signingTime
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	// Algorithm says which cryptographic generation the signer's certificate
	// belongs to and what to do about it — RK is mid-transition between GOST
	// generations, so the algorithm name alone is not actionable.
	Algorithm   AlgorithmInfo     `json:"algorithm"`
	CAdESLevel  string            `json:"cadesLevel,omitempty"`
	Certificate ReportCertificate `json:"certificate"`
	Chain       ReportChain       `json:"chain"`
}

// ReportCertificate is the signer certificate reduced to what identifies it and
// bounds its validity.
type ReportCertificate struct {
	SerialNumber string     `json:"serialNumber,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	Expired      bool       `json:"expired,omitempty"`
}

// ReportChain summarizes what the service established about the signer's chain.
type ReportChain struct {
	Complete            bool `json:"complete"`
	AnchoredInTrust     bool `json:"anchoredInTrust"`
	SignaturesVerified  bool `json:"signaturesVerified"`
	CertificatesInChain int  `json:"certificatesInChain,omitempty"`
}

// buildReport turns a completed verification into the card. checkedAt is the
// instant the verification was performed; the diagnosis is rebuilt here so the
// report does not depend on the caller also asking for explain.
func buildReport(out VerifyOutput, checkCertTime, chainVerifyOn bool, sig, content []byte, checkedAt time.Time) *VerificationReport {
	diag := out.Explanation
	if diag == nil {
		diag = buildDiagnosis(out, checkCertTime, chainVerifyOn, checkedAt)
	}
	rep := &VerificationReport{
		Verdict:   verdictFrom(out, diag),
		CheckedAt: checkedAt,
		Document: ReportDocument{
			Format:          out.Format,
			Detached:        out.Detached,
			SignatureSHA256: digestOf(sig),
			ContentSHA256:   digestOf(content),
			ContentBytes:    len(content),
		},
		Steps: diag.Steps,
	}
	for _, w := range out.Warnings {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: %s", w.Field, w.Reason))
	}
	for _, s := range out.Signers {
		rep.Signers = append(rep.Signers, reportSigner(s, checkedAt))
	}
	rep.Summary = reportSummary(rep, diag)
	return rep
}

// verdictFrom maps the verification onto the three-valued verdict: a failed
// check makes it invalid, an undeterminable one leaves it indeterminate, and only
// a clean pass is valid.
func verdictFrom(out VerifyOutput, diag *Diagnosis) ReportVerdict {
	if !out.Valid {
		return VerdictInvalid
	}
	for _, step := range diag.Steps {
		switch step.Status {
		case DiagFail:
			return VerdictInvalid
		case DiagUnknown:
			return VerdictIndeterminate
		}
	}
	return VerdictValid
}

func reportSigner(s Signer, now time.Time) ReportSigner {
	subj := s.Certificate.Subject
	rs := ReportSigner{
		Name:               signerName(subj),
		IIN:                subj.IIN,
		BIN:                subj.BIN,
		Organization:       subj.Organization,
		OwnerType:          s.Certificate.OwnerType,
		Roles:              s.Certificate.Roles,
		Valid:              s.Valid,
		SignatureAlgorithm: s.SignatureAlgorithm,
		Algorithm:          algorithmInfo(s.Certificate),
		CAdESLevel:         s.CAdESLevel,
		Certificate: ReportCertificate{
			SerialNumber: s.Certificate.SerialNumber,
			Issuer:       s.Certificate.Issuer.CommonName,
			NotBefore:    s.Certificate.NotBefore,
			NotAfter:     s.Certificate.NotAfter,
			Expired:      s.Certificate.NotAfter != nil && now.After(*s.Certificate.NotAfter),
		},
		Chain: ReportChain{
			Complete:            s.ChainComplete,
			AnchoredInTrust:     s.TrustAnchorFound,
			SignaturesVerified:  s.ChainSignaturesVerified,
			CertificatesInChain: len(s.Chain),
		},
	}
	// A TSA token is third-party evidence of when the signature existed; the
	// signing-time attribute is only the signer's own assertion, so the source is
	// reported alongside the time.
	switch {
	case s.Timestamp != nil && s.Timestamp.GenTime != nil:
		rs.SignedAt, rs.SignedAtSource = s.Timestamp.GenTime, "timestamp"
	case s.SigningTime != nil:
		rs.SignedAt, rs.SignedAtSource = s.SigningTime, "signingTime"
	}
	return rs
}

// signerName reuses the OIDC name derivation and falls back to the organization,
// so a legal-person certificate without personal name parts still reads as an
// entity rather than as an empty field.
func signerName(s Subject) string {
	if name := displayName(s); name != "" {
		return name
	}
	return s.Organization
}

func reportSummary(rep *VerificationReport, diag *Diagnosis) string {
	who := ""
	if len(rep.Signers) > 0 {
		who = rep.Signers[0].Name
		if n := len(rep.Signers); n > 1 {
			who = fmt.Sprintf("%s and %d more", who, n-1)
		}
	}
	switch rep.Verdict {
	case VerdictValid:
		if who == "" {
			return "Signature is valid."
		}
		return fmt.Sprintf("Signature is valid; signed by %s.", who)
	case VerdictIndeterminate:
		return fmt.Sprintf("Signature could not be fully confirmed: %s", diag.Summary)
	default:
		return fmt.Sprintf("Signature is not valid: %s", diag.Summary)
	}
}

func digestOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
