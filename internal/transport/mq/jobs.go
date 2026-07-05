package mq

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
)

// Job envelope operations mirror the REST job endpoints over request/reply MQ:
//   job-submit  request={op, request, callbackUrl?} → reply=job status view
//   job-status  request={id}                        → reply=job status view
//   job-result  request={id}                        → reply={status, result}
//   job-cancel  request={id}                        → reply=job status view
//
// Push-delivery of a finished job's result to a reply destination is out of
// scope here (it would couple the manager to a broker publisher); a consumer
// polls job-status/job-result, exactly as a REST client polls GET /jobs/{id}.

// jobSubmitEnvelope is the job-submit payload: the wrapped op and its request.
type jobSubmitEnvelope struct {
	Op          string          `json:"op"`
	Request     json.RawMessage `json:"request"`
	CallbackURL string          `json:"callbackUrl,omitempty"`
}

type jobIDEnvelope struct {
	ID string `json:"id"`
}

// jobResultMsg is the job-result reply: the terminal status plus the operation
// output (empty for a failed/canceled job).
type jobResultMsg struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
}

// isJobOp reports whether op is one of the async-job envelope operations.
func isJobOp(op string) bool {
	switch op {
	case "job-submit", "job-status", "job-result", "job-cancel":
		return true
	default:
		return false
	}
}

// handleJob services a job-* envelope op via the manager, publishing exactly one
// reply. It returns the publish error (if any) for the adapter to act on.
func (p *Processor) handleJob(ctx context.Context, req Request, corrID string, outcome *string, publish PublishFunc) error {
	if p.jobs == nil {
		*outcome = "client_error"
		return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Error: &ReplyError{
			Kind: core.KindName(core.KindUnsupported), Message: "async jobs are disabled",
		}}))
	}

	switch req.Op {
	case "job-submit":
		var s jobSubmitEnvelope
		if err := json.Unmarshal(req.Request, &s); err != nil {
			return p.jobReply(corrID, req.Op, outcome, nil, &core.Error{Kind: core.KindInvalid, Op: "job-submit"}, publish)
		}
		v, err := p.jobs.Submit(ctx, s.Op, s.Request, s.CallbackURL)
		return p.jobViewReply(corrID, req.Op, outcome, v, err, publish)

	case "job-status":
		id, ok := jobID(req.Request)
		if !ok {
			return p.jobReply(corrID, req.Op, outcome, nil, &core.Error{Kind: core.KindInvalid, Op: "job-status"}, publish)
		}
		v, err := p.jobs.Get(ctx, id)
		return p.jobViewReply(corrID, req.Op, outcome, v, err, publish)

	case "job-result":
		id, ok := jobID(req.Request)
		if !ok {
			return p.jobReply(corrID, req.Op, outcome, nil, &core.Error{Kind: core.KindInvalid, Op: "job-result"}, publish)
		}
		raw, st, err := p.jobs.Result(ctx, id)
		if err != nil {
			return p.jobReply(corrID, req.Op, outcome, nil, err, publish)
		}
		msg, _ := json.Marshal(jobResultMsg{Status: string(st), Result: raw})
		return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: req.Op, Result: msg}))

	case "job-cancel":
		id, ok := jobID(req.Request)
		if !ok {
			return p.jobReply(corrID, req.Op, outcome, nil, &core.Error{Kind: core.KindInvalid, Op: "job-cancel"}, publish)
		}
		if err := p.jobs.Cancel(ctx, id); err != nil {
			return p.jobReply(corrID, req.Op, outcome, nil, err, publish)
		}
		v, err := p.jobs.Get(ctx, id)
		return p.jobViewReply(corrID, req.Op, outcome, v, err, publish)
	}
	return nil // unreachable: isJobOp gates the switch
}

// jobViewReply publishes a job status view, or an error reply when err is set.
func (p *Processor) jobViewReply(corrID, op string, outcome *string, v jobs.View, err error, publish PublishFunc) error {
	if err != nil {
		return p.jobReply(corrID, op, outcome, nil, err, publish)
	}
	body, _ := json.Marshal(v)
	return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: op, Result: body}))
}

// jobReply publishes a job error reply, mapping the manager sentinel to a kind.
func (p *Processor) jobReply(corrID, op string, outcome *string, _ json.RawMessage, err error, publish PublishFunc) error {
	*outcome = jobOutcome(err)
	return publish(corrID, encodeReply(Reply{CorrelationID: corrID, Op: op, Error: jobReplyError(err)}))
}

// jobID extracts the id from a {"id":"…"} payload.
func jobID(raw json.RawMessage) (string, bool) {
	var e jobIDEnvelope
	if err := json.Unmarshal(raw, &e); err != nil || e.ID == "" {
		return "", false
	}
	return e.ID, true
}

// jobReplyError maps a manager error to the reply error envelope.
func jobReplyError(err error) *ReplyError {
	kind := core.KindInternal
	msg := err.Error()
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		kind, msg = core.KindInvalid, "job not found"
	case errors.Is(err, jobs.ErrInvalidOp):
		kind, msg = core.KindInvalid, "unknown operation"
	case errors.Is(err, jobs.ErrTooLarge):
		kind, msg = core.KindInvalid, "request too large for an inline job"
	case errors.Is(err, jobs.ErrNotReady):
		kind, msg = core.KindUnavailable, "job not finished"
	case errors.Is(err, jobs.ErrBusy):
		kind, msg = core.KindUnavailable, "job queue full"
	default:
		var de *core.Error
		if errors.As(err, &de) {
			kind = de.Kind
		}
	}
	return &ReplyError{Kind: core.KindName(kind), Message: msg}
}

// jobOutcome maps a manager error to a metric outcome label.
func jobOutcome(err error) string {
	switch {
	case errors.Is(err, jobs.ErrBusy):
		return "server_error"
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrInvalidOp),
		errors.Is(err, jobs.ErrTooLarge), errors.Is(err, jobs.ErrNotReady):
		return "client_error"
	default:
		return "server_error"
	}
}
