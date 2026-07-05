package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/transport/dto"
)

// Batch endpoints mirror the single-call ones under /{op}/batch. The aggregated
// response is {total, succeeded, failed, results:[...]}; with streaming
// requested (Accept: application/x-ndjson or ?stream=1) each result is emitted
// as its own NDJSON line as it completes — tagged with its index for reordering —
// followed by a final summary line, so a large batch never buffers in memory.

func (s *Server) handleSignBatch(w http.ResponseWriter, r *http.Request) {
	items, opts, ok := decodeBatch(w, r, dto.SignRequest.ToCore, "SignBatch")
	if !ok {
		return
	}
	writeBatch(w, r, func(ctx context.Context, sink func(core.BatchItem[core.SignOutput])) core.BatchOutput[core.SignOutput] {
		return s.svc.SignBatch(ctx, items, opts, sink)
	})
}

func (s *Server) handleVerifyBatch(w http.ResponseWriter, r *http.Request) {
	items, opts, ok := decodeBatch(w, r, dto.VerifyRequest.ToCore, "VerifyBatch")
	if !ok {
		return
	}
	writeBatch(w, r, func(ctx context.Context, sink func(core.BatchItem[core.VerifyOutput])) core.BatchOutput[core.VerifyOutput] {
		return s.svc.VerifyBatch(ctx, items, opts, sink)
	})
}

func (s *Server) handleExtractBatch(w http.ResponseWriter, r *http.Request) {
	items, opts, ok := decodeBatch(w, r, dto.ExtractRequest.ToCore, "ExtractBatch")
	if !ok {
		return
	}
	writeBatch(w, r, func(ctx context.Context, sink func(core.BatchItem[core.ExtractOutput])) core.BatchOutput[core.ExtractOutput] {
		return s.svc.ExtractBatch(ctx, items, opts, sink)
	})
}

func (s *Server) handleCertInfoBatch(w http.ResponseWriter, r *http.Request) {
	items, opts, ok := decodeBatch(w, r, dto.CertInfoToCore, "CertInfoBatch")
	if !ok {
		return
	}
	writeBatch(w, r, func(ctx context.Context, sink func(core.BatchItem[core.CertInfoOutput])) core.BatchOutput[core.CertInfoOutput] {
		return s.svc.CertInfoBatch(ctx, items, opts, sink)
	})
}

func (s *Server) handleValidateBatch(w http.ResponseWriter, r *http.Request) {
	items, opts, ok := decodeBatch(w, r, dto.ValidateToCore, "ValidateBatch")
	if !ok {
		return
	}
	writeBatch(w, r, func(ctx context.Context, sink func(core.BatchItem[core.ValidateOutput])) core.BatchOutput[core.ValidateOutput] {
		return s.svc.ValidateBatch(ctx, items, opts, sink)
	})
}

// decodeBatch reads a BatchRequest[R] body, maps items with conv and returns the
// core inputs plus options. On a bad body or a structurally invalid item it
// writes a 400 and reports ok=false.
func decodeBatch[R, I any](w http.ResponseWriter, r *http.Request, conv func(R) (I, error), op string) ([]I, core.BatchOptions, bool) {
	var req dto.BatchRequest[R]
	if !decode(w, r, &req) {
		return nil, core.BatchOptions{}, false
	}
	items, err := dto.BatchItems(req.Items, conv)
	if err != nil {
		writeError(w, &core.Error{Kind: core.KindInvalid, Op: op}, err.Error())
		return nil, core.BatchOptions{}, false
	}
	return items, req.Options(), true
}

// batchSummary is the trailing NDJSON line of a streamed batch. It carries no
// per-item results (those were already streamed), keeping the stream O(1) in
// memory; a client distinguishes it from item lines by the absence of "index".
type batchSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// writeBatch runs a batch and encodes the result: an aggregated JSON object, or
// (when streaming was requested) an NDJSON stream of per-item lines plus a
// summary line. run binds the Service.*Batch call and forwards the streaming
// sink; runBatch serializes sink calls, so writing from it needs no extra lock.
func writeBatch[O any](w http.ResponseWriter, r *http.Request, run func(ctx context.Context, sink func(core.BatchItem[O])) core.BatchOutput[O]) {
	ctx := r.Context()
	if !wantsStream(r) {
		writeJSON(w, http.StatusOK, run(ctx, nil))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flush, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	out := run(ctx, func(it core.BatchItem[O]) {
		_ = enc.Encode(it)
		if flush != nil {
			flush.Flush()
		}
	})
	_ = enc.Encode(batchSummary{Total: out.Total, Succeeded: out.Succeeded, Failed: out.Failed})
}

// wantsStream reports whether the caller asked for an NDJSON stream, via the
// stream query flag or an application/x-ndjson Accept header.
func wantsStream(r *http.Request) bool {
	switch r.URL.Query().Get("stream") {
	case "1", "true", "yes":
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "application/x-ndjson")
}
