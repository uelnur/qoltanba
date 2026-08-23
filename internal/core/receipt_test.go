package core

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// stubSigner records what it was asked to sign and returns a fake compact JWS,
// so the test exercises the domain's receipt logic without an RSA key.
type stubSigner struct {
	claims ReceiptClaims
	err    error
}

func (s *stubSigner) KeyID() string { return "test-kid" }

func (s *stubSigner) Sign(claims any) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	c, ok := claims.(ReceiptClaims)
	if !ok {
		return "", errNotReceipt
	}
	s.claims = c
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(payload) + ".sig", nil
}

var errNotReceipt = &stubError{"signer received something other than receipt claims"}

type stubError struct{ msg string }

func (e *stubError) Error() string { return e.msg }

func TestIssueReceipt_AttestsTheReport(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	signer := &stubSigner{}
	svc := New(nil, WithReceiptSigner(signer, "https://qoltanba.example"))

	report := buildReport(VerifyOutput{Valid: true, Signers: []Signer{validSigner(now)}},
		true, false, []byte("sig"), []byte("doc"), now)
	token, err := svc.issueReceipt(report, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token is not a compact JWS: %q", token)
	}
	got := signer.claims
	if got.Type != receiptType {
		t.Errorf("typ = %q, want %q — a receipt must not be mistaken for an id_token", got.Type, receiptType)
	}
	if got.Issuer != "https://qoltanba.example" || got.IssuedAt != now.Unix() {
		t.Errorf("issuer/iat wrong: %+v", got)
	}
	if got.Verdict != report.Verdict || got.Report == nil {
		t.Errorf("receipt does not carry the verdict and report: %+v", got)
	}
	// The digests are what make the attestation about specific bytes.
	if got.Report.Document.SignatureSHA256 == "" {
		t.Error("receipt must bind to the signature digest")
	}
	if len(got.ID) != 32 {
		t.Errorf("jti = %q, want a 128-bit hex id", got.ID)
	}
}

// TestIssueReceipt_UniquePerCall keeps receipts distinguishable in an audit log.
func TestIssueReceipt_UniquePerCall(t *testing.T) {
	now := time.Now()
	signer := &stubSigner{}
	svc := New(nil, WithReceiptSigner(signer, "iss"))
	report := buildReport(VerifyOutput{Valid: true}, true, false, []byte("sig"), nil, now)

	if _, err := svc.issueReceipt(report, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	first := signer.claims.ID
	if _, err := svc.issueReceipt(report, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if signer.claims.ID == first {
		t.Error("two receipts share a jti")
	}
}

// TestIssueReceipt_WithoutSignerIsSilent pins the degradation: asking for a
// receipt on a service that cannot sign must not fail the verification.
func TestIssueReceipt_WithoutSignerIsSilent(t *testing.T) {
	svc := New(nil)
	token, err := svc.issueReceipt(&VerificationReport{}, time.Now())
	if err != nil || token != "" {
		t.Errorf("token = %q, err = %v; want silent no-op", token, err)
	}
}

func TestIssueReceipt_SignerFailureSurfaces(t *testing.T) {
	svc := New(nil, WithReceiptSigner(&stubSigner{err: &stubError{"key unusable"}}, "iss"))
	if _, err := svc.issueReceipt(&VerificationReport{}, time.Now()); err == nil {
		t.Fatal("a signing failure must be reported")
	}
}
