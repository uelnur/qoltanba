// Package nats is the NATS transport: a JetStream durable consumer that reads
// request-envelope messages, dispatches each to the domain service via
// mq.Processor, and publishes the reply envelope to the message's reply subject
// (or a configured one), keyed by correlation id. It holds no crypto logic —
// only broker I/O.
//
// Delivery contract: explicit (manual) ack, and a message is acked only after
// its reply is published, so a crash redelivers the job. The stream backing the
// request subject is the consumer's to provision — we bind a durable consumer to
// it, we do not create it.
package nats

import (
	"context"
	"log/slog"
	"sync"

	"github.com/nats-io/nats.go"

	"github.com/uelnur/qoltanba/internal/transport/mq"
)

// Config configures the NATS JetStream consumer.
type Config struct {
	URL          string // nats://…
	Subject      string // request subject to consume
	Queue        string // queue group for horizontal load balancing (optional)
	ReplySubject string // fallback reply subject when a message carries no reply-to
	Durable      string // durable consumer name
}

// Consumer runs a NATS JetStream request/reply loop over the domain service.
type Consumer struct {
	cfg  Config
	proc *mq.Processor
	sem  mq.Semaphore
	log  *slog.Logger
	wg   sync.WaitGroup
}

// New builds a Consumer. concurrency bounds in-flight operations (the worker count).
func New(proc *mq.Processor, cfg Config, concurrency int, log *slog.Logger) *Consumer {
	return &Consumer{cfg: cfg, proc: proc, sem: mq.NewSemaphore(concurrency), log: log}
}

// Run connects, binds a durable JetStream consumer, and serves until ctx is
// canceled, then drains in-flight work and closes the connection. It blocks; a
// connect or subscribe failure is returned so the caller can abort startup.
func (c *Consumer) Run(ctx context.Context) error {
	nc, err := nats.Connect(c.cfg.URL,
		nats.MaxReconnects(-1),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
			c.log.Error("nats async", "error", e)
		}),
	)
	if err != nil {
		return err
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	// procCtx keeps trace values but is not canceled on shutdown, so callbacks that
	// Drain flushes still finish (publish + ack) instead of aborting. ctx governs
	// only when we stop the subscription.
	procCtx := context.WithoutCancel(ctx)
	handler := func(m *nats.Msg) {
		if !c.sem.Acquire(procCtx) {
			return
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer c.sem.Release()
			c.handle(procCtx, nc, m)
		}()
	}

	opts := []nats.SubOpt{nats.Durable(c.cfg.Durable), nats.ManualAck(), nats.AckExplicit()}
	var sub *nats.Subscription
	if c.cfg.Queue != "" {
		sub, err = js.QueueSubscribe(c.cfg.Subject, c.cfg.Queue, handler, opts...)
	} else {
		sub, err = js.Subscribe(c.cfg.Subject, handler, opts...)
	}
	if err != nil {
		return err
	}

	<-ctx.Done()
	_ = sub.Drain() // stop new deliveries, let queued callbacks start
	c.wg.Wait()     // let in-flight operations publish + ack
	return nil
}

// handle processes one message and publishes its reply, acking only after a
// successful publish so a failure leaves the message for JetStream redelivery.
func (c *Consumer) handle(ctx context.Context, nc *nats.Conn, m *nats.Msg) {
	reply, corrID := c.proc.Process(ctx, m.Data, corrIDFromHeader(m))

	replyTo := m.Reply
	if replyTo == "" {
		replyTo = c.cfg.ReplySubject
	}
	if replyTo == "" {
		_ = m.Ack() // nowhere to reply — fire-and-forget
		return
	}

	msg := nats.NewMsg(replyTo)
	msg.Data = reply
	if corrID != "" {
		msg.Header.Set(nats.MsgIdHdr, corrID)
	}
	if err := nc.PublishMsg(msg); err != nil {
		c.log.Error("nats publish reply", "error", err, "subject", replyTo)
		return // no ack → redelivered
	}
	if err := m.AckSync(); err != nil {
		// Best-effort: fall back to a plain ack before giving up.
		_ = m.Ack()
	}
}

// corrIDFromHeader reads the correlation id a producer may set as the Nats-Msg-Id
// header, used when the request envelope omits its own.
func corrIDFromHeader(m *nats.Msg) string {
	if m.Header == nil {
		return ""
	}
	return m.Header.Get(nats.MsgIdHdr)
}
