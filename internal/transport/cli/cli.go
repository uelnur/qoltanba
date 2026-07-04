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
func Run(ctx context.Context, svc *core.Service, op string, in io.Reader, out io.Writer) int {
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
	return 0
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
	_ = encode(out, map[string]any{
		"error": map[string]string{"kind": kindName(kind), "message": err.Error()},
	})
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

func kindName(k core.ErrorKind) string {
	switch k {
	case core.KindInvalid:
		return "invalid"
	case core.KindUnsupported:
		return "unsupported"
	case core.KindUnavailable:
		return "unavailable"
	case core.KindCanceled:
		return "canceled"
	default:
		return "internal"
	}
}
