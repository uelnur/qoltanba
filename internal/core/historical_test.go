package core

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/uelnur/qoltanba/internal/provider"
)

// fixedClock returns a clock pinned to t, for the future/now guards.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestWithinValidityAt(t *testing.T) {
	nb := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := Certificate{NotBefore: &nb, NotAfter: &na}

	cases := []struct {
		name              string
		cert              Certificate
		at                time.Time
		within, determine bool
	}{
		{"within", cert, time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC), true, true},
		{"before-window", cert, time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC), false, true},
		{"after-window", cert, time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), false, true},
		{"on-notBefore", cert, nb, true, true},
		{"on-notAfter", cert, na, true, true},
		{"missing-bounds", Certificate{}, time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			within, determinate := withinValidityAt(c.cert, c.at)
			if within != c.within || determinate != c.determine {
				t.Errorf("within=%v determinate=%v, want %v/%v", within, determinate, c.within, c.determine)
			}
		})
	}
}

// revokedOCSP builds an OCSP response DER marking leafSerial revoked at revTime,
// for the enrichment path (parsed with issuer=nil, signature not checked).
func revokedOCSP(t *testing.T, revTime time.Time, reason int) []byte {
	t.Helper()
	issuer, ikey, leaf := issuerAndLeaf(t, 0x99AA)
	respDER, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status: ocsp.Revoked, SerialNumber: leaf.SerialNumber,
		ThisUpdate: revTime, ProducedAt: revTime,
		RevokedAt: revTime, RevocationReason: reason,
	}, ikey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return respDER
}

func TestRevocationAt(t *testing.T) {
	revTime := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	cert := Certificate{PEM: []byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")}
	// The stub certificate carries no AIA, so the responder is named explicitly.
	viaResponder := VerifyAtInput{ResponderURL: "http://ocsp.test.example/"}

	t.Run("good-now-was-good-before", func(t *testing.T) {
		f := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusGood}}
		s := New(f)
		var v PointInTimeVerdict
		notRevoked, det := s.revocationAt(context.Background(), cert, revTime, viaResponder, &v)
		if !notRevoked || !det {
			t.Fatalf("notRevoked=%v determinate=%v, want true/true", notRevoked, det)
		}
	})

	t.Run("revoked-before-instant", func(t *testing.T) {
		f := &fakeProvider{validateResult: provider.ValidateResult{
			Status: provider.StatusRevoked, OCSPResponse: revokedOCSP(t, revTime, ocsp.KeyCompromise),
		}}
		s := New(f)
		var v PointInTimeVerdict
		at := revTime.Add(24 * time.Hour) // after revocation
		notRevoked, det := s.revocationAt(context.Background(), cert, at, viaResponder, &v)
		if notRevoked || !det {
			t.Fatalf("notRevoked=%v determinate=%v, want false/true", notRevoked, det)
		}
		if !v.RevokedAsOfAt || v.RevocationTime == nil {
			t.Errorf("RevokedAsOfAt=%v RevocationTime=%v", v.RevokedAsOfAt, v.RevocationTime)
		}
	})

	t.Run("revoked-after-instant-still-valid-then", func(t *testing.T) {
		f := &fakeProvider{validateResult: provider.ValidateResult{
			Status: provider.StatusRevoked, OCSPResponse: revokedOCSP(t, revTime, ocsp.KeyCompromise),
		}}
		s := New(f)
		var v PointInTimeVerdict
		at := revTime.Add(-24 * time.Hour) // before revocation
		notRevoked, det := s.revocationAt(context.Background(), cert, at, viaResponder, &v)
		if !notRevoked || !det {
			t.Fatalf("notRevoked=%v determinate=%v, want true/true", notRevoked, det)
		}
		if v.RevokedAsOfAt {
			t.Error("RevokedAsOfAt should be false when revocation postdates the instant")
		}
	})

	t.Run("revoked-without-time-is-indeterminate", func(t *testing.T) {
		// Revoked status but no OCSP response to date it → cannot place vs instant.
		f := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusRevoked}}
		s := New(f)
		var v PointInTimeVerdict
		notRevoked, det := s.revocationAt(context.Background(), cert, revTime, viaResponder, &v)
		if notRevoked || det {
			t.Fatalf("notRevoked=%v determinate=%v, want false/false", notRevoked, det)
		}
	})

	t.Run("hold-adds-reversibility-caveat", func(t *testing.T) {
		const reasonCertificateHold = 6
		f := &fakeProvider{validateResult: provider.ValidateResult{
			Status: provider.StatusRevoked, OCSPResponse: revokedOCSP(t, revTime, reasonCertificateHold),
		}}
		s := New(f)
		var v PointInTimeVerdict
		s.revocationAt(context.Background(), cert, revTime.Add(time.Hour), viaResponder, &v)
		if v.RevocationReason != "certificateHold" {
			t.Fatalf("reason = %q, want certificateHold", v.RevocationReason)
		}
		if !hasReasonContaining(v.Reasons, "reversible") {
			t.Errorf("expected a reversibility caveat, got %v", v.Reasons)
		}
	})

	t.Run("no-certificate-is-indeterminate", func(t *testing.T) {
		s := New(&fakeProvider{})
		var v PointInTimeVerdict
		notRevoked, det := s.revocationAt(context.Background(), Certificate{}, revTime, viaResponder, &v)
		if !notRevoked || det {
			t.Fatalf("notRevoked=%v determinate=%v, want true/false", notRevoked, det)
		}
	})
}

func TestVerifyAt_Guards(t *testing.T) {
	s := New(&fakeProvider{}, WithClock(fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))))

	if _, err := s.VerifyAt(context.Background(), VerifyAtInput{VerifyInput: VerifyInput{Format: FormatCMS}}); err == nil {
		t.Error("zero At should be rejected")
	}
	future := VerifyAtInput{VerifyInput: VerifyInput{Format: FormatCMS}, At: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := s.VerifyAt(context.Background(), future); err == nil {
		t.Error("future At should be rejected")
	}
}

func TestVerifyAt_NoSigners(t *testing.T) {
	f := &fakeProvider{verifyResult: provider.VerifyResult{Valid: false}}
	s := New(f, WithClock(fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))))
	out, err := s.VerifyAt(context.Background(), VerifyAtInput{
		VerifyInput: VerifyInput{Format: FormatCMS, Signature: []byte("x")},
		At:          time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("VerifyAt: %v", err)
	}
	if out.ValidAt {
		t.Error("no signer → ValidAt must be false")
	}
	if !out.Determinate {
		t.Error("no signer is a determinate 'not valid'")
	}
}

func TestVerifyAt_EndToEnd_ValidThen(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeProvider{
		verifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		// Certificate whose window brackets `at`; validation reports good.
		props: fields(map[string]string{
			"SUBJECT_COMMONNAME": "ТЕСТОВ ТЕСТ",
			"NOTBEFORE":          "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":           "01.01.2023 00:00:00 +00:00",
		}),
		validateResult: provider.ValidateResult{Status: provider.StatusGood},
	}
	s := New(f, WithClock(fixedClock(now)))

	out, err := s.VerifyAt(context.Background(), VerifyAtInput{
		VerifyInput: VerifyInput{Format: FormatCMS, Signature: []byte("sig")},
		At:          at,
	})
	if err != nil {
		t.Fatalf("VerifyAt: %v", err)
	}
	if !out.ValidAt || !out.Determinate {
		t.Fatalf("ValidAt=%v Determinate=%v, want true/true; signers=%+v", out.ValidAt, out.Determinate, out.Signers)
	}
	if len(out.Signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(out.Signers))
	}
	v := out.Signers[0].Verdict
	if !v.SignatureValid || !v.WithinValidity || !v.NotRevokedAt {
		t.Errorf("verdict facts: sig=%v within=%v notRevoked=%v", v.SignatureValid, v.WithinValidity, v.NotRevokedAt)
	}
	if !v.At.Equal(at) {
		t.Errorf("verdict.At = %v, want %v", v.At, at)
	}
}

func TestVerifyAt_EndToEnd_ExpiredButRevokedLater(t *testing.T) {
	// The core historical case: certificate is expired today, but at `at` it was
	// inside its window and only revoked afterwards → valid then.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	revokedLater := time.Date(2022, 12, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeProvider{
		verifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		props: fields(map[string]string{
			"NOTBEFORE": "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":  "01.01.2023 00:00:00 +00:00", // expired relative to `now`
		}),
		validateResult: provider.ValidateResult{
			Status: provider.StatusRevoked, OCSPResponse: revokedOCSP(t, revokedLater, ocsp.KeyCompromise),
		},
	}
	s := New(f, WithClock(fixedClock(now)))

	out, err := s.VerifyAt(context.Background(), VerifyAtInput{
		VerifyInput: VerifyInput{Format: FormatCMS, Signature: []byte("sig")},
		At:          at,
	})
	if err != nil {
		t.Fatalf("VerifyAt: %v", err)
	}
	if !out.ValidAt || !out.Determinate {
		t.Fatalf("ValidAt=%v Determinate=%v, want true/true (valid at instant, revoked later)", out.ValidAt, out.Determinate)
	}
	if out.Signers[0].Verdict.RevokedAsOfAt {
		t.Error("should not be revoked as of the instant")
	}
}

// hasReasonContaining reports whether any reason includes sub.
func hasReasonContaining(reasons []string, sub string) bool {
	for _, r := range reasons {
		if len(sub) > 0 && containsFold(r, sub) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
