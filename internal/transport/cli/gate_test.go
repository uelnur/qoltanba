package cli

import (
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
)

// TestVerified covers the gate's judgement over each result shape it understands.
func TestVerified(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want bool
	}{
		{"valid verify", core.VerifyOutput{Valid: true}, true},
		{"invalid verify", core.VerifyOutput{Valid: false}, false},
		{"clean register", core.RegistryOutput{Total: 2, Valid: 2}, true},
		{"register with an invalid row", core.RegistryOutput{Total: 2, Valid: 1, Invalid: 1}, false},
		{"register with an unconfirmed row", core.RegistryOutput{Total: 1, Indeterminate: 1}, false},
		{"batch all valid", core.BatchOutput[core.VerifyOutput]{
			Total: 1, Results: []core.BatchItem[core.VerifyOutput]{{Output: &core.VerifyOutput{Valid: true}}},
		}, true},
		{"batch with an invalid item", core.BatchOutput[core.VerifyOutput]{
			Total: 1, Results: []core.BatchItem[core.VerifyOutput]{{Output: &core.VerifyOutput{Valid: false}}},
		}, false},
		{"batch with a failed item", core.BatchOutput[core.VerifyOutput]{
			Total: 1, Failed: 1, Results: []core.BatchItem[core.VerifyOutput]{{}},
		}, false},
		// The gate must not judge operations it does not understand.
		{"sign output", core.SignOutput{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verified(tc.in); got != tc.want {
				t.Errorf("verified() = %v, want %v", got, tc.want)
			}
		})
	}
}
