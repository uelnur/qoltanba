package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// A batch runs the same operation over many items at once. It is the general
// surface of every operation — a single call is just a batch of one — so the
// per-item semantics (error isolation, ordering) are defined here once and every
// transport maps onto them.

// BatchPolicy controls how a batch reacts to a failing item.
type BatchPolicy string

const (
	// PolicyContinue runs every item; a failure is isolated to its own result.
	// This is the default.
	PolicyContinue BatchPolicy = "continue-on-error"
	// PolicyFailFast stops dispatching new items after the first hard failure.
	// Items already running finish; not-yet-started items stay ItemSkipped.
	PolicyFailFast BatchPolicy = "fail-fast"
)

// normalized returns the policy, defaulting an empty/unknown value to continue.
func (p BatchPolicy) normalized() BatchPolicy {
	if p == PolicyFailFast {
		return PolicyFailFast
	}
	return PolicyContinue
}

// BatchOptions are the per-batch execution controls shared by every operation.
type BatchOptions struct {
	Policy BatchPolicy
	// Concurrency caps how many items run in parallel. A value <= 0 defaults to
	// the driver pool size — beyond that items only queue at the pool anyway.
	Concurrency int
}

// ItemStatus is the per-item outcome in a batch.
type ItemStatus string

const (
	ItemOK      ItemStatus = "ok"
	ItemError   ItemStatus = "error"
	ItemSkipped ItemStatus = "skipped" // fail-fast left it unrun
)

// BatchItemError renders a failed item's domain error without leaking secrets: a
// stable kind plus the friendly catalog message/action and raw KCR_* code. It is
// the batch/async counterpart of the transport hard-error envelope.
type BatchItemError struct {
	Kind    string `json:"kind"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

// itemErrorFrom renders a domain error into a BatchItemError (nil for a nil error).
func itemErrorFrom(err error) *BatchItemError {
	if err == nil {
		return nil
	}
	kind := KindInternal
	var de *Error
	if errors.As(err, &de) {
		kind = de.Kind
	}
	exp := Explain(err)
	msg := exp.Message
	if msg == "" {
		msg = err.Error()
	}
	return &BatchItemError{Kind: KindName(kind), Code: exp.Code, Message: msg, Action: exp.Action}
}

// BatchItem is one element's result, tagged with its request index so aggregate
// and streaming consumers can both restore order. Exactly one of Output or Error
// is set for a run item; a skipped item has neither.
type BatchItem[T any] struct {
	Index  int             `json:"index"`
	Status ItemStatus      `json:"status"`
	Output *T              `json:"output,omitempty"`
	Error  *BatchItemError `json:"error,omitempty"`
}

// BatchOutput is the aggregate batch result: a summary plus per-item results in
// the original request order.
type BatchOutput[T any] struct {
	Total     int            `json:"total"`
	Succeeded int            `json:"succeeded"`
	Failed    int            `json:"failed"`
	Results   []BatchItem[T] `json:"results"`
}

// runBatch executes fn over items with bounded concurrency under the given
// policy. sink, if non-nil, receives each item as it completes (completion order,
// serialized) for streaming consumers; the returned Results slice is ordered by
// request index for aggregate consumers.
//
// It is a free function, not a method, because Go methods cannot take type
// parameters; the Service.*Batch wrappers below bind it to each operation.
func runBatch[I, O any](
	ctx context.Context,
	opts BatchOptions,
	defaultConc int,
	items []I,
	fn func(context.Context, I) (O, error),
	sink func(BatchItem[O]),
) BatchOutput[O] {
	n := len(items)
	results := make([]BatchItem[O], n)
	for i := range results {
		results[i] = BatchItem[O]{Index: i, Status: ItemSkipped}
	}

	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConc
	}
	if conc < 1 {
		conc = 1
	}

	failFast := opts.Policy.normalized() == PolicyFailFast
	var (
		mu        sync.Mutex // serializes sink and the counters
		failed    atomic.Bool
		succeeded int
		failedN   int
		wg        sync.WaitGroup
		sem       = make(chan struct{}, conc)
	)

	for i := range items {
		if ctx.Err() != nil || (failFast && failed.Load()) {
			break // remaining items stay ItemSkipped
		}
		sem <- struct{}{} // acquire — a full pool blocks here (backpressure)
		if failFast && failed.Load() {
			<-sem
			break
		}
		wg.Add(1)
		go func(idx int, item I) {
			defer wg.Done()
			defer func() { <-sem }()

			out, err := fn(ctx, item)
			res := BatchItem[O]{Index: idx}
			if err != nil {
				res.Status = ItemError
				res.Error = itemErrorFrom(err)
				if failFast {
					failed.Store(true)
				}
			} else {
				res.Status = ItemOK
				res.Output = &out
			}
			results[idx] = res // disjoint index — no lock needed for the slot

			mu.Lock()
			if err != nil {
				failedN++
			} else {
				succeeded++
			}
			if sink != nil {
				sink(res)
			}
			mu.Unlock()
		}(i, items[i])
	}
	wg.Wait()

	return BatchOutput[O]{Total: n, Succeeded: succeeded, Failed: failedN, Results: results}
}

// SignBatch signs many items. See runBatch for ordering and isolation semantics.
func (s *Service) SignBatch(ctx context.Context, items []SignInput, opts BatchOptions, sink func(BatchItem[SignOutput])) BatchOutput[SignOutput] {
	return runBatch(ctx, opts, s.batchConcurrency(), items, s.Sign, sink)
}

// VerifyBatch verifies many items.
func (s *Service) VerifyBatch(ctx context.Context, items []VerifyInput, opts BatchOptions, sink func(BatchItem[VerifyOutput])) BatchOutput[VerifyOutput] {
	return runBatch(ctx, opts, s.batchConcurrency(), items, s.Verify, sink)
}

// ExtractBatch recovers content from many signatures.
func (s *Service) ExtractBatch(ctx context.Context, items []ExtractInput, opts BatchOptions, sink func(BatchItem[ExtractOutput])) BatchOutput[ExtractOutput] {
	return runBatch(ctx, opts, s.batchConcurrency(), items, s.Extract, sink)
}

// CertInfoBatch parses many certificates.
func (s *Service) CertInfoBatch(ctx context.Context, items []CertInfoInput, opts BatchOptions, sink func(BatchItem[CertInfoOutput])) BatchOutput[CertInfoOutput] {
	return runBatch(ctx, opts, s.batchConcurrency(), items, s.CertInfo, sink)
}

// ValidateBatch checks revocation for many certificates.
func (s *Service) ValidateBatch(ctx context.Context, items []ValidateInput, opts BatchOptions, sink func(BatchItem[ValidateOutput])) BatchOutput[ValidateOutput] {
	return runBatch(ctx, opts, s.batchConcurrency(), items, s.Validate, sink)
}

// batchConcurrency is the default parallelism for a batch: the driver pool size,
// which is the real ceiling (extra goroutines just queue at the pool).
func (s *Service) batchConcurrency() int {
	if n := s.prov.Capabilities().PoolSize; n > 0 {
		return n
	}
	return 1
}
