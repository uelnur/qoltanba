package dto

import (
	"fmt"

	"github.com/uelnur/qoltanba/internal/core"
)

// BatchRequest is the wire shape of a batch call: a list of op-specific items
// (each identical to the single-call body) plus batch-wide controls. A single
// call is just a batch of one — the item shape never changes.
type BatchRequest[R any] struct {
	Items       []R    `json:"items"`
	Policy      string `json:"policy,omitempty"`      // continue-on-error (default) | fail-fast
	Concurrency int    `json:"concurrency,omitempty"` // 0 = driver pool size
}

// Options maps the batch-wide controls to the domain options.
func (b BatchRequest[R]) Options() core.BatchOptions {
	return core.BatchOptions{Policy: core.BatchPolicy(b.Policy), Concurrency: b.Concurrency}
}

// BatchItems maps each wire item to its core input with conv, failing on the
// first structurally invalid item. Structural faults (unknown format/encoding)
// are request-level — a malformed item aborts the batch rather than becoming a
// per-item outcome, which is reserved for crypto/operation failures.
func BatchItems[R, I any](items []R, conv func(R) (I, error)) ([]I, error) {
	out := make([]I, len(items))
	for i, it := range items {
		c, err := conv(it)
		if err != nil {
			return nil, fmt.Errorf("items[%d]: %w", i, err)
		}
		out[i] = c
	}
	return out, nil
}

// CertInfoToCore / ValidateToCore adapt the two error-free ToCore methods to the
// (value, error) shape BatchItems expects, so every operation maps through one
// helper (the sign/verify/extract ToCore methods already return an error).

func CertInfoToCore(r CertInfoRequest) (core.CertInfoInput, error) { return r.ToCore(), nil }
func ValidateToCore(r ValidateRequest) (core.ValidateInput, error) { return r.ToCore(), nil }
