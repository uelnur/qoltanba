package core

import (
	"errors"
	"fmt"

	"github.com/uelnur/qoltanba/internal/provider"
)

// warnings accumulates best-effort extraction misses for one response. A missing
// certificate property never fails the operation; it is recorded here with the
// underlying KCR_* code when available.
type warnings struct {
	items []Warning
}

// add records a miss for field with a reason string.
func (w *warnings) add(field, reason string) {
	w.items = append(w.items, Warning{Field: field, Reason: reason})
}

// addErr records a miss for field, extracting the KCR_* code from a provider
// error when present.
func (w *warnings) addErr(field string, err error) {
	var ne *provider.NativeError
	if errors.As(err, &ne) {
		w.add(field, fmt.Sprintf("0x%08X", ne.Code))
		return
	}
	w.add(field, err.Error())
}

// list returns the accumulated warnings (nil if none), suitable for a response.
func (w *warnings) list() []Warning {
	return w.items
}
