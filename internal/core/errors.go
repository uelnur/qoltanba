package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/uelnur/qoltanba/internal/provider"
)

// ErrorKind classifies a domain failure so transports can pick a status without
// knowing crypto details (REST → HTTP code, CLI → exit code).
type ErrorKind int

const (
	// KindInvalid is a client/request fault: bad input, wrong password, missing
	// key, a trusted CA required but absent.
	KindInvalid ErrorKind = iota
	// KindUnsupported: the loaded library version does not expose the operation.
	KindUnsupported
	// KindUnavailable: the service/library is not ready (self-test pending, closed).
	KindUnavailable
	// KindCanceled: the caller's context ended.
	KindCanceled
	// KindInternal: an unexpected failure.
	KindInternal
)

// NewError builds a domain Error with a message and classified kind. It lets an
// infrastructure adapter (e.g. the data resolver) surface a typed failure the
// transports render consistently, instead of a bare error the domain would
// classify as internal.
func NewError(kind ErrorKind, op, msg string) *Error {
	return &Error{Kind: kind, Op: op, err: errors.New(msg)}
}

// KindName is the stable lowercase label for an ErrorKind, shared by every
// transport's error envelope so the wire vocabulary is defined once.
func KindName(k ErrorKind) string {
	switch k {
	case KindInvalid:
		return "invalid"
	case KindUnsupported:
		return "unsupported"
	case KindUnavailable:
		return "unavailable"
	case KindCanceled:
		return "canceled"
	default:
		return "internal"
	}
}

// Error is a domain-level error carrying a Kind and the operation name. It wraps
// the underlying provider error so errors.Is/As still reach the sentinels.
type Error struct {
	Kind ErrorKind
	Op   string
	err  error
}

func (e *Error) Error() string {
	if e.err == nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Kind)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.err)
}

func (e *Error) Unwrap() error { return e.err }

// domainErr wraps err into an *Error with the classified kind. Returns nil for a
// nil err.
func domainErr(op string, err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Kind: classify(err), Op: op, err: err}
}

// classify maps a provider/context error to an ErrorKind.
func classify(err error) ErrorKind {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return KindCanceled
	case errors.Is(err, provider.ErrUnsupported):
		return KindUnsupported
	case errors.Is(err, provider.ErrNotReady), errors.Is(err, provider.ErrClosed):
		return KindUnavailable
	case errors.Is(err, provider.ErrInvalidPassword),
		errors.Is(err, provider.ErrKeyNotFound),
		errors.Is(err, provider.ErrCertNotFound),
		errors.Is(err, provider.ErrCertExpired),
		errors.Is(err, provider.ErrCertTimeInvalid),
		errors.Is(err, provider.ErrCertParse),
		errors.Is(err, provider.ErrSignFormatMismatch),
		errors.Is(err, provider.ErrXMLParse),
		errors.Is(err, provider.ErrCMSFormat),
		errors.Is(err, provider.ErrInvalidParam),
		errors.Is(err, provider.ErrCARequired):
		return KindInvalid
	default:
		return KindInternal
	}
}

// isSoftVerifyFailure reports whether a verify-time error is an expected
// business outcome (an invalid/absent signature or a failed chain) that belongs
// in the response's LibError with Valid=false, rather than a transport error.
func isSoftVerifyFailure(err error) bool {
	switch {
	case errors.Is(err, provider.ErrSignatureInvalid),
		errors.Is(err, provider.ErrNoSignature),
		errors.Is(err, provider.ErrChainInvalid),
		errors.Is(err, provider.ErrCertExpired),
		errors.Is(err, provider.ErrCertTimeInvalid):
		return true
	default:
		// A bare NativeError with a code but no recognized sentinel is also a
		// verify outcome, not an infra fault.
		var ne *provider.NativeError
		return errors.As(err, &ne) && !errors.Is(err, provider.ErrUnsupported) &&
			!errors.Is(err, provider.ErrNotReady) && !errors.Is(err, provider.ErrClosed)
	}
}

// localeKey carries the caller's language through the context. The domain does
// not know about HTTP headers or flags — a transport resolves the language and
// puts it here, so a per-request locale reaches the error rendering without
// threading a parameter through every operation.
type localeKey struct{}

// ContextWithLocale returns ctx carrying the language errors should be rendered
// in. An unsupported or empty tag falls back to English.
func ContextWithLocale(ctx context.Context, tag string) context.Context {
	return context.WithValue(ctx, localeKey{}, provider.ParseLocale(tag))
}

// LocaleFrom returns the language carried by ctx, defaulting to English.
func LocaleFrom(ctx context.Context) provider.Locale {
	if loc, ok := ctx.Value(localeKey{}).(provider.Locale); ok {
		return loc
	}
	return provider.LocaleEN
}

// libErrorFrom builds a response LibError from a provider error, exposing the raw
// KCR_* code and text plus the friendly Key/Message/Action from the error catalog,
// rendered in the caller's language. Key and Code stay stable across languages —
// they are the contract; only the prose changes.
func libErrorFrom(ctx context.Context, err error) *LibError {
	if err == nil {
		return nil
	}
	le := &LibError{Text: err.Error()}
	var ne *provider.NativeError
	if errors.As(err, &ne) {
		le.Code = fmt.Sprintf("0x%08X", ne.Code)
		le.Text = ne.Detail
	}
	exp := provider.Localize(provider.Explain(err), LocaleFrom(ctx))
	le.Key, le.Message, le.Action = exp.Key, exp.Message, exp.Action
	return le
}

// ExplainIn renders a domain/provider error for a transport's hard-error envelope
// in the caller's language.
func ExplainIn(ctx context.Context, err error) provider.Explanation {
	return provider.Localize(Explain(err), LocaleFrom(ctx))
}

// Explain renders a domain/provider error into a friendly Explanation for a
// transport's hard-error envelope. It resolves the caller's context errors here
// (the crypto catalog does not know about them) and delegates the rest to the
// provider error catalog. Returns the zero value for a nil error.
func Explain(err error) provider.Explanation {
	if err == nil {
		return provider.Explanation{}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return provider.Explanation{Key: "request.canceled",
			Message: "The request was canceled.",
			Action:  "Retry the request."}
	case errors.Is(err, context.DeadlineExceeded):
		return provider.Explanation{Key: "request.timeout",
			Message: "The request timed out.",
			Action:  "Retry, or increase the timeout."}
	}
	return provider.Explain(err)
}
