package core

import (
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/pki"
)

func TestAlgorithmInfo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cert       Certificate
		want       AlgorithmGeneration
		wantAdvice bool
	}{
		{"gost2015-512 is current", Certificate{KeyAlgorithm: "gost2015-512"}, GenerationCurrent, false},
		{"gost2015-256 is current", Certificate{KeyAlgorithm: "gost2015-256"}, GenerationCurrent, false},
		{"gost2004 is legacy", Certificate{KeyAlgorithm: "gost2004"}, GenerationLegacy, true},
		{"sha1WithRSA is weak", Certificate{
			KeyAlgorithm: "rsa", SignatureAlgorithmOID: pki.SignSHA1RSA,
		}, GenerationWeak, true},
		{"sha256WithRSA is legacy", Certificate{
			KeyAlgorithm: "rsa", SignatureAlgorithmOID: pki.SignSHA256RSA,
		}, GenerationLegacy, true},
		{"unknown stays unknown", Certificate{}, GenerationUnknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := algorithmInfo(tc.cert)
			if got.Generation != tc.want {
				t.Errorf("generation = %q, want %q", got.Generation, tc.want)
			}
			if hasAdvice := got.Advice != ""; hasAdvice != tc.wantAdvice {
				t.Errorf("advice = %q, want present=%v", got.Advice, tc.wantAdvice)
			}
			if got.KeyAlgorithm != tc.cert.KeyAlgorithm {
				t.Errorf("keyAlgorithm = %q, want %q", got.KeyAlgorithm, tc.cert.KeyAlgorithm)
			}
		})
	}
}

// TestAlgorithmAdviceNamesTheTarget keeps the migration hint actionable: it must
// say what to move to, not merely that something is old.
func TestAlgorithmAdviceNamesTheTarget(t *testing.T) {
	for _, cert := range []Certificate{
		{KeyAlgorithm: "gost2004"},
		{KeyAlgorithm: "rsa", SignatureAlgorithmOID: pki.SignSHA1RSA},
		{KeyAlgorithm: "rsa", SignatureAlgorithmOID: pki.SignSHA256RSA},
	} {
		if advice := algorithmInfo(cert).Advice; !strings.Contains(advice, "34.10-2015") {
			t.Errorf("advice for %q does not name the target profile: %q", cert.KeyAlgorithm, advice)
		}
	}
}

// TestLegacySignaturesStayVerifiable pins the transition policy: an old profile is
// reported, not rejected — signatures made under it must keep verifying.
func TestLegacySignaturesStayVerifiable(t *testing.T) {
	for _, cert := range []Certificate{
		{KeyAlgorithm: "gost2004"},
		{KeyAlgorithm: "rsa", SignatureAlgorithmOID: pki.SignSHA256RSA},
	} {
		if advice := algorithmInfo(cert).Advice; !strings.Contains(advice, "stay verifiable") {
			t.Errorf("advice for %q should say old signatures remain valid: %q", cert.KeyAlgorithm, advice)
		}
	}
}
