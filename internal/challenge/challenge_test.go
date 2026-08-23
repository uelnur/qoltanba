package challenge

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// fakeVerifier stands in for the domain: it records what it was asked to verify
// and returns a configured outcome, so the flow is exercised without Kalkan.
type fakeVerifier struct {
	verified  core.VerifyInput
	out       core.VerifyOutput
	verifyErr error

	validated core.ValidateInput
	valOut    core.ValidateOutput
	valErr    error
}

func (f *fakeVerifier) Verify(_ context.Context, in core.VerifyInput) (core.VerifyOutput, error) {
	f.verified = in
	return f.out, f.verifyErr
}

func (f *fakeVerifier) Validate(_ context.Context, in core.ValidateInput) (core.ValidateOutput, error) {
	f.validated = in
	return f.valOut, f.valErr
}

func signedBy(name, iin string) core.VerifyOutput {
	return core.VerifyOutput{
		Valid: true,
		Signers: []core.Signer{{
			Valid:       true,
			Certificate: core.Certificate{Subject: core.Subject{CommonName: name, IIN: iin}, PEM: []byte("pem")},
			Claims:      &core.Claims{Name: name, IIN: iin},
		}},
	}
}

func newService(t *testing.T, v Verifier, cfg Config) *Service {
	t.Helper()
	s := New(v, NewMemStore(), cfg)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIssueAndConfirm(t *testing.T) {
	v := &fakeVerifier{out: signedBy("ТЕСТОВ ТЕСТ", "123456789011")}
	s := newService(t, v, Config{})

	issued, err := s.Issue(context.Background(), IssueRequest{
		Purpose: "payment.confirm",
		Meta:    map[string]string{"orderId": "42"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Alg != SigningForm || issued.Purpose != "payment.confirm" {
		t.Errorf("issue response = %+v", issued)
	}
	nonce, err := base64.StdEncoding.DecodeString(issued.Data)
	if err != nil || len(nonce) != nonceBytes {
		t.Fatalf("nonce = %q (%v), want %d random bytes", issued.Data, err, nonceBytes)
	}

	got, err := s.Confirm(context.Background(), ConfirmRequest{
		ChallengeID: issued.ChallengeID, Signature: []byte("cms"),
	})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !got.Confirmed || got.Signer == nil || got.Signer.IIN != "123456789011" {
		t.Errorf("confirm = %+v", got)
	}
	// The purpose and meta must survive the round trip: they are what stop a
	// signature gathered for one action from authorizing another.
	if got.Purpose != "payment.confirm" || got.Meta["orderId"] != "42" {
		t.Errorf("purpose/meta lost: %+v", got)
	}
	// The signature must have been checked against the issued nonce, detached.
	if !bytes.Equal(v.verified.Data, nonce) || !v.verified.Detached {
		t.Errorf("verified over %q (detached=%v), want the issued nonce", v.verified.Data, v.verified.Detached)
	}
}

// TestConfirmIsSingleUse is the anti-replay guarantee: a captured signature
// cannot be presented twice.
func TestConfirmIsSingleUse(t *testing.T) {
	s := newService(t, &fakeVerifier{out: signedBy("X", "1")}, Config{})
	issued, _ := s.Issue(context.Background(), IssueRequest{})

	if _, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID}); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	_, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID})
	if !errors.Is(err, ErrUsed) {
		t.Fatalf("second confirm err = %v, want ErrUsed", err)
	}
}

// TestConfirmBurnsChallengeOnBadSignature keeps a rejected attempt from being
// retried against the same nonce.
func TestConfirmBurnsChallengeOnBadSignature(t *testing.T) {
	v := &fakeVerifier{out: core.VerifyOutput{Valid: false}}
	s := newService(t, v, Config{})
	issued, _ := s.Issue(context.Background(), IssueRequest{Purpose: "p"})

	got, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got.Confirmed {
		t.Error("an invalid signature must not confirm")
	}
	if _, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID}); !errors.Is(err, ErrUsed) {
		t.Errorf("retry after a bad signature err = %v, want ErrUsed", err)
	}
}

func TestConfirmRejectsExpired(t *testing.T) {
	now := time.Now()
	s := New(&fakeVerifier{out: signedBy("X", "1")}, NewMemStore(), Config{TTL: time.Minute},
		WithClock(func() time.Time { return now }))
	issued, _ := s.Issue(context.Background(), IssueRequest{})

	now = now.Add(2 * time.Minute)
	if _, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID}); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestConfirmUnknownChallenge(t *testing.T) {
	s := newService(t, &fakeVerifier{}, Config{})
	if _, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: "nope"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestConfirmRevocation covers the opt-in revocation leg in both directions.
func TestConfirmRevocation(t *testing.T) {
	t.Run("revoked signer is not confirmed", func(t *testing.T) {
		v := &fakeVerifier{out: signedBy("X", "1")}
		v.valOut = core.ValidateOutput{Status: core.RevocationStatus{Revoked: true}}
		s := newService(t, v, Config{RequireOCSP: true})
		issued, _ := s.Issue(context.Background(), IssueRequest{})

		got, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID})
		if err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if got.Confirmed || got.Revoked == nil || !*got.Revoked {
			t.Errorf("confirm = %+v, want unconfirmed and revoked", got)
		}
	})

	t.Run("inconclusive check fails closed", func(t *testing.T) {
		v := &fakeVerifier{out: signedBy("X", "1")}
		v.valOut = core.ValidateOutput{Status: core.RevocationStatus{
			LibError: &core.LibError{Message: "responder unreachable"},
		}}
		s := newService(t, v, Config{RequireOCSP: true})
		issued, _ := s.Issue(context.Background(), IssueRequest{})

		if _, err := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID}); err == nil {
			t.Error("an unusable revocation answer must fail the confirmation, not pass it")
		}
	})

	t.Run("off by default", func(t *testing.T) {
		v := &fakeVerifier{out: signedBy("X", "1")}
		s := newService(t, v, Config{})
		issued, _ := s.Issue(context.Background(), IssueRequest{})

		got, _ := s.Confirm(context.Background(), ConfirmRequest{ChallengeID: issued.ChallengeID})
		if got.Revoked != nil || v.validated.Cert != nil {
			t.Errorf("revocation checked without being asked: %+v", got)
		}
	})

	t.Run("per-request opt-in", func(t *testing.T) {
		v := &fakeVerifier{out: signedBy("X", "1")}
		s := newService(t, v, Config{})
		issued, _ := s.Issue(context.Background(), IssueRequest{})

		got, err := s.Confirm(context.Background(), ConfirmRequest{
			ChallengeID: issued.ChallengeID, CheckRevocation: true,
		})
		if err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if got.Revoked == nil || *got.Revoked {
			t.Errorf("revoked = %v, want a performed check reporting false", got.Revoked)
		}
	})
}

func TestReapAndActive(t *testing.T) {
	now := time.Now()
	s := New(&fakeVerifier{}, NewMemStore(), Config{TTL: time.Minute},
		WithClock(func() time.Time { return now }))
	if _, err := s.Issue(context.Background(), IssueRequest{}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if s.Active() != 1 {
		t.Fatalf("active = %d, want 1", s.Active())
	}
	now = now.Add(2 * time.Minute)
	if n, err := s.Reap(context.Background()); err != nil || n != 1 {
		t.Fatalf("reaped %d (%v), want 1", n, err)
	}
	if s.Active() != 0 {
		t.Errorf("active = %d after reap, want 0", s.Active())
	}
}
