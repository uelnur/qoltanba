package core

import (
	"strings"
	"testing"
	"time"
)

// validSigner builds a signer whose every check passes at now.
func validSigner(now time.Time) Signer {
	nb, na := now.Add(-24*time.Hour), now.Add(24*time.Hour)
	signed := now.Add(-time.Hour)
	return Signer{
		Certificate: Certificate{
			Subject:      Subject{CommonName: "ТЕСТОВ ТЕСТ", IIN: "123456789011"},
			Issuer:       Subject{CommonName: "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ"},
			SerialNumber: "1f2e3d",
			NotBefore:    &nb,
			NotAfter:     &na,
			OwnerType:    "INDIVIDUAL",
			Roles:        []string{"INDIVIDUAL"},
		},
		Valid:              true,
		SigningTime:        &signed,
		SignatureAlgorithm: "GOST R 34.10-2015 512",
		ChainComplete:      true,
		TrustAnchorFound:   true,
		Revocation:         &RevocationStatus{Determinate: true, Method: MethodOCSP},
	}
}

func TestBuildReport_ValidSignature(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	out := VerifyOutput{Valid: true, Format: FormatCMS, Signers: []Signer{validSigner(now)}}

	rep := buildReport(out, true, false, []byte("signature-bytes"), []byte("content"), now)

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %q, want valid", rep.Verdict)
	}
	if rep.Summary == "" || rep.Signers[0].Name != "ТЕСТОВ ТЕСТ" {
		t.Errorf("summary/name not rendered: %+v", rep)
	}
	if rep.Signers[0].IIN != "123456789011" || rep.Signers[0].OwnerType != "INDIVIDUAL" {
		t.Errorf("identity fields lost: %+v", rep.Signers[0])
	}
	if !rep.CheckedAt.Equal(now) {
		t.Errorf("checkedAt = %v, want %v", rep.CheckedAt, now)
	}
	if len(rep.Steps) == 0 {
		t.Error("expected the diagnosis steps to be carried in the card")
	}
}

// TestBuildReport_BindsToBytes pins what makes a report usable as evidence: it
// names the exact bytes it is about.
func TestBuildReport_BindsToBytes(t *testing.T) {
	now := time.Now()
	rep := buildReport(VerifyOutput{Valid: true}, true, false, []byte("sig"), []byte("doc"), now)

	if rep.Document.SignatureSHA256 == "" || rep.Document.SignatureSHA256 == rep.Document.ContentSHA256 {
		t.Fatalf("digests missing or identical: %+v", rep.Document)
	}
	if len(rep.Document.SignatureSHA256) != 64 || len(rep.Document.ContentSHA256) != 64 {
		t.Errorf("digests are not hex sha256: %+v", rep.Document)
	}
	if rep.Document.ContentBytes != 3 {
		t.Errorf("contentBytes = %d, want 3", rep.Document.ContentBytes)
	}
	// An absent content must not produce a digest of nothing.
	bare := buildReport(VerifyOutput{Valid: true}, true, false, []byte("sig"), nil, now)
	if bare.Document.ContentSHA256 != "" {
		t.Errorf("content digest = %q, want empty when there is no content", bare.Document.ContentSHA256)
	}
}

func TestBuildReport_InvalidSignature(t *testing.T) {
	now := time.Now()
	out := VerifyOutput{Valid: false, Format: FormatCMS}

	rep := buildReport(out, true, false, []byte("sig"), nil, now)

	if rep.Verdict != VerdictInvalid {
		t.Errorf("verdict = %q, want invalid", rep.Verdict)
	}
	if rep.Summary == "" {
		t.Error("an invalid verdict must still explain itself")
	}
}

// TestBuildReport_IndeterminateWhenCheckUnknown covers the distinction the
// verdict exists for: a check that could not be performed is not a failure.
func TestBuildReport_IndeterminateWhenCheckUnknown(t *testing.T) {
	now := time.Now()
	signer := validSigner(now)
	signer.Certificate.NotBefore, signer.Certificate.NotAfter = nil, nil // validity window unknown
	out := VerifyOutput{Valid: true, Signers: []Signer{signer}}

	rep := buildReport(out, true, false, []byte("sig"), nil, now)

	if rep.Verdict != VerdictIndeterminate {
		t.Fatalf("verdict = %q, want indeterminate (steps: %+v)", rep.Verdict, rep.Steps)
	}
}

// TestBuildReport_PrefersTimestampOverSigningTime pins the evidential ordering: a
// TSA token outranks the signer's own claim about when it signed.
func TestBuildReport_PrefersTimestampOverSigningTime(t *testing.T) {
	now := time.Now()
	signer := validSigner(now)
	stamped := now.Add(-30 * time.Minute)
	signer.Timestamp = &Timestamp{GenTime: &stamped, TSA: "tsp.pki.gov.kz"}

	rep := buildReport(VerifyOutput{Valid: true, Signers: []Signer{signer}}, true, false, nil, nil, now)

	got := rep.Signers[0]
	if got.SignedAtSource != "timestamp" || got.SignedAt == nil || !got.SignedAt.Equal(stamped) {
		t.Errorf("signedAt = %v (%s), want the timestamp %v", got.SignedAt, got.SignedAtSource, stamped)
	}

	signer.Timestamp = nil
	rep = buildReport(VerifyOutput{Valid: true, Signers: []Signer{signer}}, true, false, nil, nil, now)
	if got := rep.Signers[0]; got.SignedAtSource != "signingTime" {
		t.Errorf("signedAtSource = %q, want signingTime when there is no token", got.SignedAtSource)
	}
}

func TestBuildReport_MultipleSignersInSummary(t *testing.T) {
	now := time.Now()
	second := validSigner(now)
	second.Certificate.Subject = Subject{Organization: "ТОО РОГА И КОПЫТА"}
	out := VerifyOutput{Valid: true, Signers: []Signer{validSigner(now), second}}

	rep := buildReport(out, true, false, nil, nil, now)

	if len(rep.Signers) != 2 {
		t.Fatalf("signers = %d, want 2", len(rep.Signers))
	}
	// A legal person without name parts still has to read as an entity.
	if rep.Signers[1].Name != "ТОО РОГА И КОПЫТА" {
		t.Errorf("second signer name = %q", rep.Signers[1].Name)
	}
	if !strings.Contains(rep.Summary, "1 more") {
		t.Errorf("summary should mention the other signers: %q", rep.Summary)
	}
}
