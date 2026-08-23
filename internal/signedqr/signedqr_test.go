package signedqr

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/oidc"
)

// realService uses the actual RS256 signer, so the round trip covers the real
// signature and the real payload size.
func realService(t *testing.T, now func() time.Time) *Service {
	t.Helper()
	signer, err := oidc.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	opts := []Option{}
	if now != nil {
		opts = append(opts, WithClock(now))
	}
	return New(signer, signer, "https://id.example", opts...)
}

func TestIssueAndVerify(t *testing.T) {
	s := realService(t, nil)

	out, err := s.Issue(IssueRequest{
		Subject: "123456789011",
		Data: map[string]any{
			"permit": "A-42",
			"until":  "2027-01-01",
		},
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if strings.Count(out.Payload, ".") != 2 {
		t.Fatalf("payload is not a compact JWS: %q", out.Payload)
	}
	if png, derr := base64.StdEncoding.DecodeString(out.QR); derr != nil || len(png) == 0 {
		t.Fatalf("QR is not a base64 PNG: %v", derr)
	}
	if out.Bytes != len(out.Payload) {
		t.Errorf("bytes = %d, want %d", out.Bytes, len(out.Payload))
	}

	res := s.Verify(out.Payload)
	if !res.Valid {
		t.Fatalf("verify = %+v", res)
	}
	if res.Subject != "123456789011" || res.Issuer != "https://id.example" {
		t.Errorf("identity lost: %+v", res)
	}
	if res.Data["permit"] != "A-42" {
		t.Errorf("data lost: %+v", res.Data)
	}
	if res.ExpiresAt == nil || res.IssuedAt == nil {
		t.Errorf("validity window lost: %+v", res)
	}
}

// TestVerifyRejectsATamperedPayload is the property the whole thing rests on.
func TestVerifyRejectsATamperedPayload(t *testing.T) {
	s := realService(t, nil)
	out, err := s.Issue(IssueRequest{Subject: "1", Data: map[string]any{"permit": "A-42"}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(out.Payload, ".")
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(
		[]byte(`{"typ":"qoltanba.signed-document.v1","sub":"1","data":{"permit":"A-999"}}`)) + "." + parts[2]

	if res := s.Verify(forged); res.Valid {
		t.Fatal("an edited payload verified")
	}
}

// TestVerifyRejectsAnExpiredDocument keeps a withdrawn permit from passing.
func TestVerifyRejectsAnExpiredDocument(t *testing.T) {
	now := time.Now()
	s := realService(t, func() time.Time { return now })

	out, err := s.Issue(IssueRequest{Subject: "1", TTLSeconds: 60})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	now = now.Add(2 * time.Minute)

	if res := s.Verify(out.Payload); res.Valid {
		t.Errorf("expired document verified: %+v", res)
	}
}

// TestVerifyRejectsAnotherTokenKind keeps a receipt or an id_token — signed by
// the very same key — from being accepted as a document.
func TestVerifyRejectsAnotherTokenKind(t *testing.T) {
	signer, err := oidc.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s := New(signer, signer, "iss")

	other, err := signer.Sign(map[string]any{
		"typ": "qoltanba.verification-receipt.v1", "sub": "1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res := s.Verify(other)
	if res.Valid {
		t.Fatal("a receipt passed as a signed document")
	}
	if !strings.Contains(res.Reason, "not a signed document") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// TestIssueRefusesAnOversizedPayload pins the deliberate refusal: a code that
// scans badly in the field is worse than an error the caller can still act on.
func TestIssueRefusesAnOversizedPayload(t *testing.T) {
	s := realService(t, nil)

	big := map[string]any{}
	for i := 0; i < 60; i++ {
		big[strings.Repeat("k", 10)+string(rune('a'+i%26))+string(rune('0'+i%10))] = strings.Repeat("v", 40)
	}
	_, err := s.Issue(IssueRequest{Subject: "1", Data: big})
	if err == nil {
		t.Fatal("an oversized payload should be refused")
	}
	if !strings.Contains(err.Error(), "scannable") {
		t.Errorf("err = %v, want it to explain why", err)
	}
}

func TestVerifyHandlesGarbage(t *testing.T) {
	s := realService(t, nil)
	for _, in := range []string{"", "   ", "not-a-jws", "a.b.c"} {
		if res := s.Verify(in); res.Valid || res.Reason == "" {
			t.Errorf("Verify(%q) = %+v, want an explained rejection", in, res)
		}
	}
}
