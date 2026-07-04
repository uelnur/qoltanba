// Package mq holds the broker-agnostic core shared by the message-queue
// transports (RabbitMQ, Kafka, NATS): the request/reply JSON envelope and a
// Processor that decodes an incoming message, dispatches it to the domain
// service, and publishes one or more reply envelopes. The per-broker adapters
// (amqp, kafka, nats sub-packages) are thin: they own connection and delivery
// I/O only and delegate every message to Processor.Process — so the mapping is
// tested once, here.
//
// Envelope, not transport metadata, is the contract. A message body is a Request
// envelope carrying the operation and its op-specific payload (the same JSON as
// REST/CLI). This keeps the wire shape identical across brokers regardless of
// which of them can carry native headers, while still letting a consumer fall
// back to a transport-native correlation id when the envelope omits one.
//
// A batch op streams one reply per item (plus a summary) over the same
// correlation id — the MQ analog of REST NDJSON. Async jobs are first-class
// envelope ops (job-submit/job-status/job-result/job-cancel) when a manager is
// wired; they mirror the REST job endpoints.
package mq

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
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
// Error is populated. For a batch op, Result carries one item per message and a
// final summary message. Result mirrors the corresponding REST/gRPC response body.
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

// PublishFunc delivers one reply envelope keyed by correlation id. A batch op
// calls it once per item plus once for the summary; every other op calls it once.
// It returns an error only on a genuine publish/infrastructure failure, which the
// adapter turns into a nack/requeue.
type PublishFunc func(corrID string, reply []byte) error

// Processor turns one raw message into one or more raw replies over the domain
// service (and, when wired, the async-job manager).
type Processor struct {
	svc  *core.Service
	jobs *jobs.Manager     // nil disables the job-* envelope ops
	rec  *metrics.Recorder // may be nil (metrics off)
}

// Option configures a Processor.
type Option func(*Processor)

// WithJobs enables the job-* envelope operations backed by the given manager.
func WithJobs(m *jobs.Manager) Option { return func(p *Processor) { p.jobs = m } }

// NewProcessor builds a Processor over the domain service. rec may be nil.
func NewProcessor(svc *core.Service, rec *metrics.Recorder, opts ...Option) *Processor {
	p := &Processor{svc: svc, rec: rec}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Process decodes the request envelope in body and publishes its reply(ies) via
// publish. It returns an error only when publish itself fails (so the adapter can
// nack/requeue); a malformed envelope, an unknown operation or a service fault is
// published as an error reply and returns nil, so the caller can always ack.
// Retry/DLQ policy is the consumer's — we impose none here.
func (p *Processor) Process(ctx context.Context, body []byte, metaCorrID string, publish PublishFunc) error {
	start := time.Now()
	op, outcome := "unknown", "ok"
	defer func() { p.rec.Observe("mq", op, outcome, time.Since(start)) }()

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		outcome = "client_error"
		return publish(metaCorrID, encodeReply(Reply{CorrelationID: metaCorrID, Error: &ReplyError{
			Kind: core.KindName(core.KindInvalid), Message: "invalid request envelope",
		}}))
	}
	if req.Op != "" {
		op = req.Op
	}
	corrID := req.CorrelationID
	if corrID == "" {
		corrID = metaCorrID
	}

	if isJobOp(req.Op) {
		return p.handleJob(ctx, req, corrID, &outcome, publish)
	}

	if !dispatch.Valid(req.Op) {
		outcome = "client_error"
		return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: &ReplyError{
			Kind: core.KindName(core.KindInvalid), Message: "unknown operation " + strconvQuote(req.Op),
		}}))
	}

	// Stream each op output: one reply for a single op, one per item plus a
	// summary for a "-batch" op. emit is called serially by the batch runner.
	var pubErr error
	emit := func(v any) {
		if pubErr != nil {
			return
		}
		result, merr := json.Marshal(v)
		if merr != nil {
			pubErr = publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: &ReplyError{
				Kind: core.KindName(core.KindInternal), Message: "encode result",
			}}))
			return
		}
		pubErr = publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Result: result}))
	}
	err := dispatch.HandleStreaming(ctx, p.svc, req.Op, req.Request, emit)
	if pubErr != nil {
		outcome = "server_error"
		return pubErr
	}
	if err != nil {
		outcome = outcomeForKind(err)
		return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: errorFrom(err)}))
	}
	return nil
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
	return &ReplyError{Kind: core.KindName(kind), Code: exp.Code, Message: msg, Action: exp.Action}
}

// strconvQuote wraps s in double quotes for error messages without pulling in
// fmt formatting rules for arbitrary runes.
func strconvQuote(s string) string { return "\"" + s + "\"" }
