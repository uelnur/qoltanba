package provider

import (
	"errors"
	"fmt"
)

// Typed port errors. The driver maps native KCR_* codes into these values, so
// no C code and no unsafe pointer ever leaks out. The domain matches them with
// errors.Is.
var (
	ErrClosed      = errors.New("provider: closed")
	ErrUnsupported = errors.New("provider: operation not supported by this library version")
	ErrNotReady    = errors.New("provider: library not ready")

	// Domain-meaningful conditions distilled from KCR_* codes.
	ErrInvalidPassword    = errors.New("provider: invalid container password")
	ErrKeyNotFound        = errors.New("provider: key not found")
	ErrCertNotFound       = errors.New("provider: certificate not found")
	ErrCertExpired        = errors.New("provider: certificate expired")
	ErrCertTimeInvalid    = errors.New("provider: certificate not valid at the given time")
	ErrSignFormatMismatch = errors.New("provider: sign/verify flag mismatch")
	ErrSignatureInvalid   = errors.New("provider: signature invalid")
	ErrNoSignature        = errors.New("provider: no signature found")
	ErrChainInvalid       = errors.New("provider: certificate chain build/verify failed")
	ErrCARequired         = errors.New("provider: trusted CA certificate required")
	ErrOCSPRequest        = errors.New("provider: OCSP request failed")
	ErrBufferTooSmall     = errors.New("provider: output buffer too small")
)

// NativeError wraps a raw Kalkan return code for cases without a dedicated
// sentinel. It carries the operation, the KCR_* code and the library's last
// error text, and unwraps to a recognized sentinel when one applies.
type NativeError struct {
	Op     string // driver operation, e.g. "SignCMS"
	Code   uint32 // raw KCR_* code (0 if unknown)
	Detail string // KC_GetLastErrorString or an explanation
	err    error  // recognized sentinel from the list above, if any
}

func (e *NativeError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: code 0x%08X: %s", e.Op, e.Code, e.Detail)
	}
	return fmt.Sprintf("%s: code 0x%08X", e.Op, e.Code)
}

// Unwrap returns the recognized sentinel so errors.Is(err, ErrInvalidPassword)
// matches a NativeError carrying the corresponding code.
func (e *NativeError) Unwrap() error { return e.err }

// NewNativeError builds a NativeError bound to a recognized sentinel.
func NewNativeError(op string, code uint32, detail string, sentinel error) *NativeError {
	return &NativeError{Op: op, Code: code, Detail: detail, err: sentinel}
}
