package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// batchProv varies ValidateCert by input so a batch test can mix successes and
// failures deterministically: a cert whose bytes start with "bad" hard-fails.
type batchProv struct {
	fake.Provider
	mu    sync.Mutex
	calls int
}

func (p *batchProv) ValidateCert(_ context.Context, req provider.ValidateRequest) (provider.ValidateResult, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if strings.HasPrefix(string(req.Cert), "bad") {
		return provider.ValidateResult{}, errors.New("boom") // hard (non-soft) fault
	}
	return provider.ValidateResult{Status: provider.StatusGood}, nil
}

func validateItems(certs ...string) []ValidateInput {
	in := make([]ValidateInput, len(certs))
	for i, c := range certs {
		in[i] = ValidateInput{Cert: []byte(c), Format: EncodingDER}
	}
	return in
}

func TestBatch_OrderAndSuccess(t *testing.T) {
	svc := New(&batchProv{Provider: fake.Provider{Caps: provider.Capabilities{PoolSize: 4}}})
	out := svc.ValidateBatch(context.Background(), validateItems("a", "b", "c", "d", "e"), BatchOptions{}, nil)

	if out.Total != 5 || out.Succeeded != 5 || out.Failed != 0 {
		t.Fatalf("summary = %+v, want total=5 succeeded=5 failed=0", out)
	}
	for i, r := range out.Results {
		if r.Index != i {
			t.Errorf("result[%d].Index = %d, want %d", i, r.Index, i)
		}
		if r.Status != ItemOK || r.Output == nil || r.Error != nil {
			t.Errorf("result[%d] = %+v, want ok with output", i, r)
		}
	}
}

func TestBatch_ContinueOnErrorIsolatesFailures(t *testing.T) {
	svc := New(&batchProv{Provider: fake.Provider{Caps: provider.Capabilities{PoolSize: 4}}})
	items := validateItems("ok0", "bad1", "ok2", "bad3", "ok4")
	out := svc.ValidateBatch(context.Background(), items, BatchOptions{Policy: PolicyContinue}, nil)

	if out.Total != 5 || out.Succeeded != 3 || out.Failed != 2 {
		t.Fatalf("summary = %+v, want total=5 succeeded=3 failed=2", out)
	}
	for _, idx := range []int{1, 3} {
		r := out.Results[idx]
		if r.Status != ItemError || r.Error == nil || r.Output != nil {
			t.Errorf("result[%d] = %+v, want error", idx, r)
		}
	}
	for _, idx := range []int{0, 2, 4} {
		if out.Results[idx].Status != ItemOK {
			t.Errorf("result[%d] = %+v, want ok", idx, out.Results[idx])
		}
	}
}

func TestBatch_FailFastSkipsRemaining(t *testing.T) {
	svc := New(&batchProv{Provider: fake.Provider{Caps: provider.Capabilities{PoolSize: 4}}})
	// Concurrency 1 makes dispatch sequential, so the failure at index 1 stops
	// every later item deterministically.
	items := validateItems("ok0", "bad1", "ok2", "ok3")
	out := svc.ValidateBatch(context.Background(), items, BatchOptions{Policy: PolicyFailFast, Concurrency: 1}, nil)

	if out.Results[0].Status != ItemOK {
		t.Errorf("result[0] = %+v, want ok", out.Results[0])
	}
	if out.Results[1].Status != ItemError {
		t.Errorf("result[1] = %+v, want error", out.Results[1])
	}
	for _, idx := range []int{2, 3} {
		if out.Results[idx].Status != ItemSkipped {
			t.Errorf("result[%d] = %+v, want skipped", idx, out.Results[idx])
		}
	}
	if out.Succeeded != 1 || out.Failed != 1 {
		t.Errorf("summary succeeded=%d failed=%d, want 1/1", out.Succeeded, out.Failed)
	}
}

func TestBatch_StreamingSinkSeesEveryRunItem(t *testing.T) {
	svc := New(&batchProv{Provider: fake.Provider{Caps: provider.Capabilities{PoolSize: 4}}})
	var mu sync.Mutex
	seen := map[int]ItemStatus{}
	svc.ValidateBatch(context.Background(), validateItems("a", "bad", "c"), BatchOptions{}, func(it BatchItem[ValidateOutput]) {
		mu.Lock()
		seen[it.Index] = it.Status
		mu.Unlock()
	})
	if len(seen) != 3 {
		t.Fatalf("sink saw %d items, want 3", len(seen))
	}
	if seen[1] != ItemError {
		t.Errorf("sink item 1 = %v, want error", seen[1])
	}
}

func TestBatch_EmptyItems(t *testing.T) {
	svc := New(&batchProv{Provider: fake.Provider{Caps: provider.Capabilities{PoolSize: 2}}})
	out := svc.ValidateBatch(context.Background(), nil, BatchOptions{}, nil)
	if out.Total != 0 || len(out.Results) != 0 {
		t.Fatalf("empty batch = %+v, want zero", out)
	}
}
