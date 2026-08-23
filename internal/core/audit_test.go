package core

import (
	"context"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// recordingSink captures what the domain reports to the journal.
type recordingSink struct{ events []AuditEvent }

func (r *recordingSink) Record(_ context.Context, ev AuditEvent) { r.events = append(r.events, ev) }

func TestAuditRecordsVerifyOutcome(t *testing.T) {
	sink := &recordingSink{}
	prov := &fakeProvider{verifyResult: provider.VerifyResult{Valid: true}}
	svc := New(prov, WithAudit(sink))

	if _, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: []byte("signature-bytes"),
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Op != "verify" || ev.Outcome != "valid" {
		t.Errorf("event = %+v", ev)
	}
	// The journal must name the artifact by digest, never carry it: an audit trail
	// is not a copy of every document that passed through.
	if ev.Subject == "" || ev.Subject == "signature-bytes" || len(ev.Subject) != 64 {
		t.Errorf("subject = %q, want a hex digest", ev.Subject)
	}
}

func TestAuditRecordsInvalidVerdict(t *testing.T) {
	sink := &recordingSink{}
	svc := New(&fakeProvider{verifyResult: provider.VerifyResult{Valid: false}}, WithAudit(sink))

	if _, err := svc.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := sink.events[0].Outcome; got != "invalid" {
		t.Errorf("outcome = %q, want invalid", got)
	}
}

func TestAuditRecordsSigning(t *testing.T) {
	sink := &recordingSink{}
	prov := &fakeProvider{
		caps:       provider.Capabilities{SignCMS: true},
		signResult: provider.SignResult{Signature: []byte("sig")},
	}
	svc := New(prov, WithKeySource(staticKeySource{}), WithAudit(sink))

	if _, err := svc.Sign(context.Background(), SignInput{
		Format: FormatCMS, Data: []byte("doc"), Key: KeySpec{Path: &PathKey{Path: "/k.p12"}},
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sink.events) != 1 || sink.events[0].Op != "sign" || sink.events[0].Outcome != "ok" {
		t.Fatalf("events = %+v", sink.events)
	}
}

// TestAuditIsOptional keeps the journal from becoming a precondition for work.
func TestAuditIsOptional(t *testing.T) {
	svc := New(&fakeProvider{verifyResult: provider.VerifyResult{Valid: true}})
	if _, err := svc.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")}); err != nil {
		t.Fatalf("verify without a journal: %v", err)
	}
}
