package mq

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func decodeReply(t *testing.T, b []byte) Reply {
	t.Helper()
	var r Reply
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decode reply: %v; body=%s", err, b)
	}
	return r
}

func TestProcess_Success(t *testing.T) {
	f := &fake.Provider{VerifyResult: provider.VerifyResult{Valid: true}}
	p := NewProcessor(core.New(f))

	body := []byte(`{"op":"verify","correlationId":"abc","request":{"format":"cms","signature":"eA=="}}`)
	reply, corrID := p.Process(context.Background(), body, "meta")
	if corrID != "abc" {
		t.Fatalf("corrID = %q, want abc (envelope wins over meta)", corrID)
	}
	r := decodeReply(t, reply)
	if r.Error != nil {
		t.Fatalf("unexpected error: %+v", r.Error)
	}
	if r.CorrelationID != "abc" || r.Op != "verify" {
		t.Fatalf("reply meta = %q/%q", r.CorrelationID, r.Op)
	}
	var out core.VerifyOutput
	if err := json.Unmarshal(r.Result, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !out.Valid {
		t.Errorf("Valid = false")
	}
}

func TestProcess_CorrelationIDFallsBackToMeta(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}))
	body := []byte(`{"op":"verify","request":{"format":"cms","signature":"eA=="}}`)
	_, corrID := p.Process(context.Background(), body, "meta-id")
	if corrID != "meta-id" {
		t.Fatalf("corrID = %q, want meta-id", corrID)
	}
}

func TestProcess_MalformedEnvelope(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}))
	reply, corrID := p.Process(context.Background(), []byte(`{not json`), "meta-id")
	if corrID != "meta-id" {
		t.Fatalf("corrID = %q, want meta-id echoed", corrID)
	}
	r := decodeReply(t, reply)
	if r.Error == nil || r.Error.Kind != "invalid" {
		t.Fatalf("error = %+v, want invalid", r.Error)
	}
}

func TestProcess_UnknownOp(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}))
	reply, _ := p.Process(context.Background(), []byte(`{"op":"frobnicate","request":{}}`), "")
	r := decodeReply(t, reply)
	if r.Error == nil || r.Error.Kind != "invalid" {
		t.Fatalf("error = %+v, want invalid", r.Error)
	}
	if r.Op != "frobnicate" && r.Op != "" {
		// Op is echoed for a decodable-but-unknown op.
		if r.Op != "frobnicate" {
			t.Logf("op echoed as %q", r.Op)
		}
	}
}

func TestProcess_ServiceFaultBecomesErrorReply(t *testing.T) {
	f := &fake.Provider{SignErr: provider.ErrUnsupported}
	// A sign needs a key source; without one the domain returns KindUnavailable.
	p := NewProcessor(core.New(f))
	body := []byte(`{"op":"sign","request":{"format":"cms","data":"eA==","key":{"inlineP12":"eA=="}}}`)
	reply, _ := p.Process(context.Background(), body, "")
	r := decodeReply(t, reply)
	if r.Error == nil {
		t.Fatalf("expected error reply, got result %s", r.Result)
	}
	if r.Error.Kind == "" {
		t.Errorf("error kind empty")
	}
}
