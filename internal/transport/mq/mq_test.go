package mq

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// collector captures every published reply so a test can assert single- or
// multi-reply behavior.
type collector struct {
	corrIDs []string
	replies [][]byte
}

func (c *collector) publish(corrID string, reply []byte) error {
	c.corrIDs = append(c.corrIDs, corrID)
	c.replies = append(c.replies, append([]byte(nil), reply...))
	return nil
}

// run processes a body and returns the collector plus any publish error.
func run(t *testing.T, p *Processor, body, meta string) *collector {
	t.Helper()
	c := &collector{}
	if err := p.Process(context.Background(), []byte(body), meta, c.publish); err != nil {
		t.Fatalf("Process returned publish error: %v", err)
	}
	return c
}

// only asserts exactly one reply was published and decodes it.
func (c *collector) only(t *testing.T) (Reply, string) {
	t.Helper()
	if len(c.replies) != 1 {
		t.Fatalf("published %d replies, want 1", len(c.replies))
	}
	var r Reply
	if err := json.Unmarshal(c.replies[0], &r); err != nil {
		t.Fatalf("decode reply: %v; body=%s", err, c.replies[0])
	}
	return r, c.corrIDs[0]
}

func TestProcess_Success(t *testing.T) {
	f := &fake.Provider{VerifyResult: provider.VerifyResult{Valid: true}}
	p := NewProcessor(core.New(f), nil)

	body := `{"op":"verify","correlationId":"abc","request":{"format":"cms","signature":"eA=="}}`
	r, corrID := run(t, p, body, "meta").only(t)
	if corrID != "abc" {
		t.Fatalf("corrID = %q, want abc (envelope wins over meta)", corrID)
	}
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
	p := NewProcessor(core.New(&fake.Provider{}), nil)
	body := `{"op":"verify","request":{"format":"cms","signature":"eA=="}}`
	_, corrID := run(t, p, body, "meta-id").only(t)
	if corrID != "meta-id" {
		t.Fatalf("corrID = %q, want meta-id", corrID)
	}
}

func TestProcess_MalformedEnvelope(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}), nil)
	r, corrID := run(t, p, `{not json`, "meta-id").only(t)
	if corrID != "meta-id" {
		t.Fatalf("corrID = %q, want meta-id echoed", corrID)
	}
	if r.Error == nil || r.Error.Kind != "invalid" {
		t.Fatalf("error = %+v, want invalid", r.Error)
	}
}

func TestProcess_UnknownOp(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}), nil)
	r, _ := run(t, p, `{"op":"frobnicate","request":{}}`, "").only(t)
	if r.Error == nil || r.Error.Kind != "invalid" {
		t.Fatalf("error = %+v, want invalid", r.Error)
	}
}

func TestProcess_ServiceFaultBecomesErrorReply(t *testing.T) {
	f := &fake.Provider{SignErr: provider.ErrUnsupported}
	// A sign needs a key source; without one the domain returns KindUnavailable.
	p := NewProcessor(core.New(f), nil)
	body := `{"op":"sign","request":{"format":"cms","data":"eA==","key":{"inlineP12":"eA=="}}}`
	r, _ := run(t, p, body, "").only(t)
	if r.Error == nil {
		t.Fatalf("expected error reply, got result %s", r.Result)
	}
	if r.Error.Kind == "" {
		t.Errorf("error kind empty")
	}
}

func TestProcess_BatchStreamsPerItemPlusSummary(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	p := NewProcessor(core.New(f), nil)

	body := `{"op":"cert-validate-batch","correlationId":"cid","request":{"items":[` +
		`{"cert":"YQ==","encoding":"der"},{"cert":"Yg==","encoding":"der"}]}}`
	c := run(t, p, body, "meta")

	// Two item messages + one summary, all under the envelope correlation id.
	if len(c.replies) != 3 {
		t.Fatalf("published %d replies, want 3 (2 items + summary)", len(c.replies))
	}
	var items, summaries int
	for i, raw := range c.replies {
		if c.corrIDs[i] != "cid" {
			t.Errorf("reply %d corrID = %q, want cid", i, c.corrIDs[i])
		}
		var r Reply
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("decode reply %d: %v", i, err)
		}
		var probe map[string]json.RawMessage
		_ = json.Unmarshal(r.Result, &probe)
		if _, ok := probe["index"]; ok {
			items++
		} else if _, ok := probe["total"]; ok {
			summaries++
		}
	}
	if items != 2 || summaries != 1 {
		t.Fatalf("got %d items, %d summaries, want 2/1", items, summaries)
	}
}
