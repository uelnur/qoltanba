package multisign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// scriptedVerifier returns the signers configured for each submitted container,
// so a test drives a co-signing round without Kalkan.
type scriptedVerifier struct {
	signers map[string][]core.ReportSigner
	invalid map[string]bool
}

func (v *scriptedVerifier) Verify(_ context.Context, in core.VerifyInput) (core.VerifyOutput, error) {
	key := string(in.Signature)
	if v.invalid[key] {
		return core.VerifyOutput{Valid: false}, nil
	}
	signers, ok := v.signers[key]
	if !ok {
		return core.VerifyOutput{Valid: false}, nil
	}
	return core.VerifyOutput{Valid: true, Report: &core.VerificationReport{
		Verdict: core.VerdictValid, Signers: signers,
	}}, nil
}

func signer(iin, name string, roles ...string) core.ReportSigner {
	return core.ReportSigner{IIN: iin, Name: name, Roles: roles, Valid: true}
}

func newService(t *testing.T, v Verifier) *Service {
	t.Helper()
	s := New(v, NewMemStore(), Config{})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRoundCompletesWhenEveryoneSigned(t *testing.T) {
	director := signer("111", "Директор")
	accountant := signer("222", "Бухгалтер")
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {director},
		"cms-2": {director, accountant},
	}}
	s := newService(t, v)

	sess, err := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Detached: true,
		Required: []Required{{IIN: "111", Label: "Директор"}, {IIN: "222", Label: "Бухгалтер"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.Status != StatusPending || len(sess.Remaining()) != 2 {
		t.Fatalf("fresh session = %+v", sess)
	}

	sess, err = s.Submit(context.Background(), sess.ID, []byte("cms-1"))
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if sess.Status != StatusPending || len(sess.Remaining()) != 1 {
		t.Fatalf("after one signature = %+v", sess)
	}
	if sess.Remaining()[0].Label != "Бухгалтер" {
		t.Errorf("remaining = %+v, want the accountant", sess.Remaining())
	}

	sess, err = s.Submit(context.Background(), sess.ID, []byte("cms-2"))
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if sess.Status != StatusComplete || len(sess.Collected) != 2 {
		t.Fatalf("after both signatures = %+v", sess)
	}
	if string(sess.Container) != "cms-2" {
		t.Errorf("container = %q, want the latest co-signed one", sess.Container)
	}
}

// TestSubmitRejectsAnUninvitedSigner is the point of tracking identity: a
// passer-by must not be able to complete someone else's document.
func TestSubmitRejectsAnUninvitedSigner(t *testing.T) {
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {signer("999", "Посторонний")},
	}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{IIN: "111"}},
	})

	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-1")); !errors.Is(err, ErrNotInvited) {
		t.Fatalf("err = %v, want ErrNotInvited", err)
	}
}

// TestSubmitRejectsADroppedSignature keeps a participant from quietly replacing
// the round with a container of their own.
func TestSubmitRejectsADroppedSignature(t *testing.T) {
	director := signer("111", "Директор")
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {director},
		"cms-2": {signer("222", "Бухгалтер")}, // director's signature is gone
	}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{IIN: "111"}, {IIN: "222"}},
	})
	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-1")); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-2")); !errors.Is(err, ErrLostSigner) {
		t.Errorf("err = %v, want ErrLostSigner", err)
	}
}

func TestSubmitRejectsResubmission(t *testing.T) {
	director := signer("111", "Директор")
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{"cms-1": {director}}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{IIN: "111"}, {IIN: "222"}},
	})
	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-1")); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-1")); !errors.Is(err, ErrNoNewSigner) {
		t.Errorf("err = %v, want ErrNoNewSigner", err)
	}
}

// TestSubmitRejectsAnInvalidContainer keeps completion meaningful: collecting a
// signature that does not verify would make "complete" a lie.
func TestSubmitRejectsAnInvalidContainer(t *testing.T) {
	v := &scriptedVerifier{invalid: map[string]bool{"broken": true}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{IIN: "111"}},
	})
	if _, err := s.Submit(context.Background(), sess.ID, []byte("broken")); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

// TestRoleRequirement covers "any first head of this organization must sign",
// where the person is not known up front.
func TestRoleRequirement(t *testing.T) {
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {core.ReportSigner{IIN: "333", BIN: "555", Name: "Кто-то", Roles: []string{"CEO"}}},
	}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{BIN: "555", Role: "ceo"}},
	})

	sess, err := s.Submit(context.Background(), sess.ID, []byte("cms-1"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if sess.Status != StatusComplete {
		t.Errorf("session = %+v, want complete", sess)
	}
}

// TestMinSignersCountsAnyone covers the "any two of us" rule.
func TestMinSignersCountsAnyone(t *testing.T) {
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {signer("111", "A")},
		"cms-2": {signer("111", "A"), signer("222", "B")},
	}}
	s := newService(t, v)
	sess, _ := s.Create(context.Background(), CreateRequest{Document: []byte("act"), MinSigners: 2})

	sess, _ = s.Submit(context.Background(), sess.ID, []byte("cms-1"))
	if sess.Status != StatusPending {
		t.Fatalf("one of two = %+v", sess)
	}
	sess, err := s.Submit(context.Background(), sess.ID, []byte("cms-2"))
	if err != nil || sess.Status != StatusComplete {
		t.Fatalf("two of two = %+v, %v", sess, err)
	}
}

func TestSeededContainerCountsExistingSignatures(t *testing.T) {
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{
		"cms-1": {signer("111", "Директор")},
	}}
	s := newService(t, v)

	sess, err := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Container: []byte("cms-1"),
		Required: []Required{{IIN: "111"}, {IIN: "222"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(sess.Collected) != 1 || len(sess.Remaining()) != 1 {
		t.Errorf("seeded session = %+v", sess)
	}
}

func TestExpiredSessionRefusesSignatures(t *testing.T) {
	now := time.Now()
	v := &scriptedVerifier{signers: map[string][]core.ReportSigner{"cms-1": {signer("111", "A")}}}
	s := New(v, NewMemStore(), Config{TTL: time.Hour}, WithClock(func() time.Time { return now }))

	sess, _ := s.Create(context.Background(), CreateRequest{
		Document: []byte("act"), Required: []Required{{IIN: "111"}},
	})
	now = now.Add(2 * time.Hour)

	got, err := s.Get(context.Background(), sess.ID)
	if err != nil || got.Status != StatusExpired {
		t.Fatalf("session = %+v, %v; want expired", got, err)
	}
	if _, err := s.Submit(context.Background(), sess.ID, []byte("cms-1")); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("err = %v, want ErrSessionClosed", err)
	}
}

func TestCreateValidatesTheRequest(t *testing.T) {
	s := newService(t, &scriptedVerifier{})
	for _, tc := range []struct {
		name string
		req  CreateRequest
	}{
		{"nothing to sign", CreateRequest{Required: []Required{{IIN: "1"}}}},
		{"nobody required", CreateRequest{Document: []byte("d")}},
		{"requirement identifies nobody", CreateRequest{Document: []byte("d"), Required: []Required{{Label: "Кто-то"}}}},
		{"unknown format", CreateRequest{Document: []byte("d"), MinSigners: 1, Format: "pdf"}},
	} {
		if _, err := s.Create(context.Background(), tc.req); err == nil {
			t.Errorf("%s: Create should fail", tc.name)
		}
	}
}
