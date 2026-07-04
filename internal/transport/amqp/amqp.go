// Package amqp is the RabbitMQ transport: it consumes request-envelope messages
// from a queue, dispatches each to the domain service via mq.Processor, and
// publishes the reply envelope to the delivery's reply-to (or a configured reply
// queue), keyed by correlation id. It holds no crypto logic — only broker I/O.
//
// Delivery contract: manual ack, and the message is acked only after its reply
// is published, so a crash mid-flight redelivers the job rather than losing it.
// Retry/DLQ beyond that is the consumer's queue policy, not ours.
package amqp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/uelnur/qoltanba/internal/transport/mq"
)

// Config configures the RabbitMQ consumer.
type Config struct {
	URL        string // amqp[s]://… (may carry credentials)
	Queue      string // request queue to consume
	ReplyQueue string // fixed reply queue; empty defers to each message's reply-to
	Prefetch   int    // channel QoS prefetch; <1 falls back to the worker count
}

// Consumer runs a RabbitMQ request/reply loop over the domain service.
type Consumer struct {
	cfg         Config
	proc        *mq.Processor
	sem         mq.Semaphore
	concurrency int
	log         *slog.Logger
}

// New builds a Consumer. concurrency bounds in-flight operations (the worker
// count); it also seeds the default prefetch.
func New(proc *mq.Processor, cfg Config, concurrency int, log *slog.Logger) *Consumer {
	return &Consumer{cfg: cfg, proc: proc, sem: mq.NewSemaphore(concurrency), concurrency: concurrency, log: log}
}

// Run dials the broker, consumes until ctx is canceled, then drains in-flight
// deliveries and closes the connection. It blocks; a dial or setup failure is
// returned so the caller can decide whether to abort startup.
func (c *Consumer) Run(ctx context.Context) error {
	conn, err := amqp.Dial(c.cfg.URL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()

	prefetch := c.cfg.Prefetch
	if prefetch < 1 {
		prefetch = c.concurrency
	}
	if err := ch.Qos(prefetch, 0, false); err != nil {
		return err
	}

	deliveries, err := ch.Consume(c.cfg.Queue, "", false /* autoAck */, false, false, false, nil)
	if err != nil {
		return err
	}

	// procCtx keeps trace values but is not canceled on shutdown, so an already
	// accepted delivery finishes (publish + ack) during drain instead of aborting
	// mid-operation. ctx governs only the accept loop.
	procCtx := context.WithoutCancel(ctx)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait() // let in-flight deliveries publish + ack before closing
			return nil
		case d, ok := <-deliveries:
			if !ok {
				wg.Wait()
				return nil // channel/connection closed by the broker
			}
			if !c.sem.Acquire(ctx) {
				wg.Wait()
				return nil
			}
			wg.Add(1)
			go func(d amqp.Delivery) {
				defer wg.Done()
				defer c.sem.Release()
				c.handle(procCtx, ch, d)
			}(d)
		}
	}
}

// handle processes one delivery and publishes its reply, acking only after a
// successful publish. Failure to publish nacks with requeue so the job is
// redelivered per the queue's policy.
func (c *Consumer) handle(ctx context.Context, ch *amqp.Channel, d amqp.Delivery) {
	reply, corrID := c.proc.Process(ctx, d.Body, d.CorrelationId)

	replyTo := d.ReplyTo
	if replyTo == "" {
		replyTo = c.cfg.ReplyQueue
	}
	if replyTo == "" {
		_ = d.Ack(false) // nowhere to reply — fire-and-forget
		return
	}

	// ctx here is the drain-safe processing context (not canceled on shutdown);
	// bound the publish so a wedged broker cannot block a worker forever.
	pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := ch.PublishWithContext(pubCtx, "", replyTo, false, false, amqp.Publishing{
		ContentType:   "application/json",
		CorrelationId: corrID,
		Body:          reply,
	})
	if err != nil {
		c.log.Error("amqp publish reply", "error", err, "replyTo", replyTo)
		_ = d.Nack(false, true) // requeue for redelivery
		return
	}
	if err := d.Ack(false); err != nil {
		c.log.Warn("amqp ack", "error", err)
	}
}
