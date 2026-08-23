// Package cli is the command-line transport: read a JSON request from stdin,
// call the domain service, write a JSON response to stdout. Like every
// transport it only maps the wire format to core inputs; no crypto lives here.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
)

// Ops lists the supported operation names (one JSON request per invocation).
var Ops = dispatch.Ops

// maxRequestBytes caps the CLI request read from stdin; large data goes by
// reference (future async model), not inline JSON.
const maxRequestBytes = 32 << 20 // 32 MiB

// Run executes one operation: it decodes a request from in, calls svc, and
// encodes the result to out. It returns a process exit code (0 on success).
// Hard failures print a JSON error envelope to out and return non-zero.
// Option configures a Run.
type Option func(*options)

type options struct{ failOnInvalid bool }

// FailOnInvalid makes a completed-but-negative verification exit non-zero. The
// default follows the API: a signature that is simply invalid is a successful
// answer, not an error. A pipeline gate needs the opposite — "this artifact does
// not verify" must stop the build — so it opts in.
func FailOnInvalid() Option { return func(o *options) { o.failOnInvalid = true } }

// ExitInvalid is the exit code of a verification that completed and came back
// negative under FailOnInvalid. It is distinct from the error codes so a script
// can tell "bad signature" from "could not check".
const ExitInvalid = 2

func Run(ctx context.Context, svc *core.Service, op string, in io.Reader, out io.Writer, opts ...Option) int {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}
	payload, err := io.ReadAll(io.LimitReader(in, maxRequestBytes))
	if err != nil {
		return encodeError(out, &core.Error{Kind: core.KindInvalid, Op: "read"})
	}
	result, err := dispatch.Handle(ctx, svc, op, payload)
	if err != nil {
		return encodeError(out, err)
	}
	if err := encode(out, result); err != nil {
		fmt.Fprintln(out, err.Error())
		return 1
	}
	if cfg.failOnInvalid && !verified(result) {
		return ExitInvalid
	}
	return 0
}

// verified reports whether a result represents a positive verification. Anything
// that is not a verification counts as verified: the gate only judges what it
// understands, and an unrelated op must not fail the build.
func verified(result any) bool {
	switch v := result.(type) {
	case core.VerifyOutput:
		return v.Valid
	case *core.VerifyOutput:
		return v != nil && v.Valid
	case core.RegistryOutput:
		return v.Invalid == 0 && v.Indeterminate == 0 && v.Failed == 0
	case *core.RegistryOutput:
		return v != nil && v.Invalid == 0 && v.Indeterminate == 0 && v.Failed == 0
	case core.BatchOutput[core.VerifyOutput]:
		return batchVerified(v)
	case *core.BatchOutput[core.VerifyOutput]:
		return v != nil && batchVerified(*v)
	default:
		return true
	}
}

func batchVerified(out core.BatchOutput[core.VerifyOutput]) bool {
	if out.Failed > 0 {
		return false
	}
	for _, item := range out.Results {
		if item.Output == nil || !item.Output.Valid {
			return false
		}
	}
	return true
}

func encode(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// encodeError writes a JSON error envelope and returns the exit code for the
// error's kind.
func encodeError(out io.Writer, err error) int {
	kind := core.KindInternal
	var de *core.Error
	if errors.As(err, &de) {
		kind = de.Kind
	}
	exp := core.Explain(err)
	detail := map[string]string{"kind": core.KindName(kind), "message": err.Error()}
	if exp.Message != "" {
		detail["message"] = exp.Message
	}
	if exp.Code != "" {
		detail["code"] = exp.Code
	}
	if exp.Action != "" {
		detail["action"] = exp.Action
	}
	_ = encode(out, map[string]any{"error": detail})
	return exitFor(kind)
}

func exitFor(k core.ErrorKind) int {
	switch k {
	case core.KindInvalid:
		return 2
	case core.KindUnsupported:
		return 3
	case core.KindUnavailable:
		return 4
	case core.KindCanceled:
		return 5
	default:
		return 1
	}
}
