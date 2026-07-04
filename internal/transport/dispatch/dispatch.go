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

// Ops lists the supported operation names, in a stable order. Each single
// operation has a "-batch" companion that takes {items, policy, concurrency} and
// returns an aggregated core.BatchOutput (the stateless transports never stream).
var Ops = []string{
	"sign", "verify", "extract", "cert-info", "cert-validate",
	"sign-batch", "verify-batch", "extract-batch", "cert-info-batch", "cert-validate-batch",
}

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
	case "sign-batch":
		return handleBatch(payload, "SignBatch", dto.SignRequest.ToCore,
			func(items []core.SignInput, o core.BatchOptions) any { return svc.SignBatch(ctx, items, o, nil) })
	case "verify-batch":
		return handleBatch(payload, "VerifyBatch", dto.VerifyRequest.ToCore,
			func(items []core.VerifyInput, o core.BatchOptions) any { return svc.VerifyBatch(ctx, items, o, nil) })
	case "extract-batch":
		return handleBatch(payload, "ExtractBatch", dto.ExtractRequest.ToCore,
			func(items []core.ExtractInput, o core.BatchOptions) any { return svc.ExtractBatch(ctx, items, o, nil) })
	case "cert-info-batch":
		return handleBatch(payload, "CertInfoBatch", dto.CertInfoToCore,
			func(items []core.CertInfoInput, o core.BatchOptions) any {
				return svc.CertInfoBatch(ctx, items, o, nil)
			})
	case "cert-validate-batch":
		return handleBatch(payload, "ValidateBatch", dto.ValidateToCore,
			func(items []core.ValidateInput, o core.BatchOptions) any {
				return svc.ValidateBatch(ctx, items, o, nil)
			})
	default:
		return nil, invalid("dispatch")
	}
}

// handleBatch decodes a BatchRequest[R], maps each item with conv, and runs it
// through run (which binds the matching Service.*Batch aggregated call). A
// malformed envelope or item yields a KindInvalid error, mirroring the singles.
func handleBatch[R, I any](payload []byte, op string, conv func(R) (I, error), run func([]I, core.BatchOptions) any) (any, error) {
	var req dto.BatchRequest[R]
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, invalid(op)
	}
	items, err := dto.BatchItems(req.Items, conv)
	if err != nil {
		return nil, invalid(op)
	}
	return run(items, req.Options()), nil
}

func invalid(op string) error { return &core.Error{Kind: core.KindInvalid, Op: op} }
