// Package mq holds the broker-agnostic core shared by the message-queue
// transports (RabbitMQ, Kafka, NATS): the request/reply JSON envelope and a
// Processor that decodes an incoming message, dispatches it to the domain
// service, and encodes the reply. The per-broker adapters (amqp, kafka, nats
// sub-packages) are thin: they own connection and delivery I/O only and delegate
// every message to Processor.Process — so the mapping is tested once, here.
//
// Envelope, not transport metadata, is the contract. A message body is a Request
// envelope carrying the operation and its op-specific payload (the same JSON as
// REST/CLI). This keeps the wire shape identical across brokers regardless of
// which of them can carry native headers, while still letting a consumer fall
// back to a transport-native correlation id when the envelope omits one.
package mq

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/metrics"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
)

// Request is the JSON envelope a consumer expects. Op selects the operation;
// Request carries the op-specific payload (identical to the REST/CLI body).
// CorrelationID, when present, is echoed on the reply and used as the routing /
// idempotency key; an empty value defers to the transport-native id.
type Request struct {
	Op            string          `json:"op"`
	CorrelationID string          `json:"correlationId,omitempty"`
	Request       json.RawMessage `json:"request"`
}

// Reply is the JSON envelope a consumer publishes back. Exactly one of Result or
// Error is populated. Result mirrors the corresponding REST/gRPC response body.
type Reply struct {
	CorrelationID string          `json:"correlationId,omitempty"`
	Op            string          `json:"op,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         *ReplyError     `json:"error,omitempty"`
}

// ReplyError is the error envelope for a failed operation, mirroring the REST
// error body: a stable kind plus a friendly message/action from the error catalog
// and the raw KCR_* code. Secrets never appear here — the message is derived from
// codes and operation names, not from user input.
type ReplyError struct {
	Kind    string `json:"kind"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

// Processor turns one raw message into one raw reply over the domain service.
type Processor struct {
	svc *core.Service
	rec *metrics.Recorder // may be nil (metrics off)
}

// NewProcessor builds a Processor over the domain service. rec may be nil.
func NewProcessor(svc *core.Service, rec *metrics.Recorder) *Processor {
	return &Processor{svc: svc, rec: rec}
}

// Process decodes the request envelope in body, dispatches to the domain service
// and returns the encoded reply envelope together with the effective correlation
// id (the envelope's value, else metaCorrID). It never returns an error: a
// malformed envelope, an unknown operation or a service fault is encoded into
// the reply's Error field, so the caller can always publish a result and then
// ack. Retry/DLQ policy is the consumer's — we impose none here.
func (p *Processor) Process(ctx context.Context, body []byte, metaCorrID string) (reply []byte, corrID string) {
	start := time.Now()
	op, outcome := "unknown", "ok"
	defer func() { p.rec.Observe("mq", op, outcome, time.Since(start)) }()

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		outcome = "client_error"
		return encodeReply(Reply{CorrelationID: metaCorrID, Error: &ReplyError{
			Kind: kindName(core.KindInvalid), Message: "invalid request envelope",
		}}), metaCorrID
	}
	if req.Op != "" {
		op = req.Op
	}
	corrID = req.CorrelationID
	if corrID == "" {
		corrID = metaCorrID
	}
	if !dispatch.Valid(req.Op) {
		outcome = "client_error"
		return encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: &ReplyError{
			Kind: kindName(core.KindInvalid), Message: "unknown operation " + strconvQuote(req.Op),
		}}), corrID
	}

	out, err := dispatch.Handle(ctx, p.svc, req.Op, req.Request)
	if err != nil {
		outcome = outcomeForKind(err)
		return encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: errorFrom(err)}), corrID
	}
	result, merr := json.Marshal(out)
	if merr != nil {
		outcome = "server_error"
		return encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: &ReplyError{
			Kind: kindName(core.KindInternal), Message: "encode result",
		}}), corrID
	}
	return encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Result: result}), corrID
}

// outcomeForKind maps a domain error to a metric outcome label, matching the
// HTTP transport's client_error/server_error split.
func outcomeForKind(err error) string {
	var de *core.Error
	if errors.As(err, &de) && de.Kind == core.KindInvalid {
		return "client_error"
	}
	return "server_error"
}

// encodeReply marshals a Reply, falling back to a minimal internal-error
// envelope if marshaling itself fails (it should not — Reply is plain data).
func encodeReply(r Reply) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		return []byte(`{"error":{"kind":"internal","message":"encode reply"}}`)
	}
	return b
}

// errorFrom maps a domain error to the reply error envelope.
func errorFrom(err error) *ReplyError {
	kind := core.KindInternal
	var de *core.Error
	if errors.As(err, &de) {
		kind = de.Kind
	}
	exp := core.Explain(err)
	msg := exp.Message
	if msg == "" {
		msg = err.Error()
	}
	return &ReplyError{Kind: kindName(kind), Code: exp.Code, Message: msg, Action: exp.Action}
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

// strconvQuote wraps s in double quotes for error messages without pulling in
// fmt formatting rules for arbitrary runes.
func strconvQuote(s string) string { return "\"" + s + "\"" }
