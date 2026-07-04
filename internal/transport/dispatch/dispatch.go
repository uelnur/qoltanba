// Package dispatch is the shared operation router for the stateless transports
// (CLI and the message-queue consumers): given an operation name and a JSON
// request payload it decodes into the domain input, calls the service, and
// returns the domain output. Centralizing the op→core mapping here makes every
// such transport speak one contract by construction; HTTP and gRPC keep their
// own per-endpoint mapping (path/proto driven) but the shapes are identical.
package dispatch

import (
	"context"
	"encoding/json"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/transport/dto"
)

// Ops lists the supported operation names, in a stable order.
var Ops = []string{"sign", "verify", "extract", "cert-info", "cert-validate"}

// Valid reports whether op names a supported operation.
func Valid(op string) bool {
	for _, o := range Ops {
		if o == op {
			return true
		}
	}
	return false
}

// Handle decodes payload as the request for op, invokes the domain service and
// returns the domain output value (a core *Output struct, ready to marshal). A
// malformed payload or an unknown op yields a KindInvalid *core.Error; genuine
// service faults propagate unchanged for the caller to classify.
func Handle(ctx context.Context, svc *core.Service, op string, payload []byte) (any, error) {
	switch op {
	case "sign":
		var req dto.SignRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, invalid("Sign")
		}
		in, err := req.ToCore()
		if err != nil {
			return nil, invalid("Sign")
		}
		return svc.Sign(ctx, in)
	case "verify":
		var req dto.VerifyRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, invalid("Verify")
		}
		in, err := req.ToCore()
		if err != nil {
			return nil, invalid("Verify")
		}
		return svc.Verify(ctx, in)
	case "extract":
		var req dto.ExtractRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, invalid("Extract")
		}
		in, err := req.ToCore()
		if err != nil {
			return nil, invalid("Extract")
		}
		return svc.Extract(ctx, in)
	case "cert-info":
		var req dto.CertInfoRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, invalid("CertInfo")
		}
		return svc.CertInfo(ctx, req.ToCore())
	case "cert-validate":
		var req dto.ValidateRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, invalid("Validate")
		}
		return svc.Validate(ctx, req.ToCore())
	default:
		return nil, invalid("dispatch")
	}
}

func invalid(op string) error { return &core.Error{Kind: core.KindInvalid, Op: op} }
