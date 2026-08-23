package audit

import (
	"context"
	"log/slog"

	"github.com/uelnur/qoltanba/internal/core"
)

// Sink adapts the journal to the domain's audit port.
//
// A failure to record must not fail the operation the caller asked for: the
// journal is evidence about work, not a precondition for doing it. A dropped
// entry is loud in the log — and visible as a gap in the sequence — rather than
// an outage.
type Sink struct {
	log *Log
	obs *slog.Logger
}

var _ core.AuditSink = (*Sink)(nil)

// NewSink wraps a journal for the domain.
func NewSink(l *Log, obs *slog.Logger) *Sink {
	if obs == nil {
		obs = slog.Default()
	}
	return &Sink{log: l, obs: obs}
}

func (s *Sink) Record(_ context.Context, ev core.AuditEvent) {
	if _, err := s.log.Append(Event{
		Op: ev.Op, Subject: ev.Subject, Signer: ev.Signer,
		Outcome: ev.Outcome, Detail: ev.Detail,
	}); err != nil {
		s.obs.Error("audit: entry not recorded", "op", ev.Op, "error", err)
	}
}
