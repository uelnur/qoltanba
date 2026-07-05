// Package kafka is the Kafka transport: a consumer-group client that reads
// request-envelope records, dispatches each to the domain service via
// mq.Processor, and produces the reply envelope to a reply topic keyed by
// correlation id. It holds no crypto logic — only broker I/O.
//
// Delivery contract: auto-commit is disabled and offsets are committed only
// after every record in a poll has had its reply published, so a crash loses no
// job (at-least-once; reprocessing is safe — crypto is idempotent by input, and
// consumers dedupe by correlation id).
package kafka

import (
	"context"
	"log/slog"
	"sync"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/uelnur/qoltanba/internal/transport/mq"
)

// replyTopicHeader lets a producer override the configured reply topic per
// message, mirroring AMQP's reply-to.
const replyTopicHeader = "reply-topic"

// Config configures the Kafka consumer.
type Config struct {
	Brokers    []string // seed brokers
	Topic      string   // request topic to consume
	ReplyTopic string   // default reply topic; a per-record header overrides it
	Group      string   // consumer group id
}

// Consumer runs a Kafka request/reply loop over the domain service.
type Consumer struct {
	cfg  Config
	proc *mq.Processor
	sem  mq.Semaphore
	log  *slog.Logger
}

// New builds a Consumer. concurrency bounds in-flight operations (the worker count).
func New(proc *mq.Processor, cfg Config, concurrency int, log *slog.Logger) *Consumer {
	return &Consumer{cfg: cfg, proc: proc, sem: mq.NewSemaphore(concurrency), log: log}
}

// Run connects, consumes until ctx is canceled, then closes the client. It
// blocks; a client-construction failure is returned so the caller can abort
// startup.
func (c *Consumer) Run(ctx context.Context) error {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(c.cfg.Brokers...),
		kgo.ConsumerGroup(c.cfg.Group),
		kgo.ConsumeTopics(c.cfg.Topic),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		return err
	}
	defer cl.Close()

	// procCtx keeps trace values but is not canceled on shutdown, so replies for
	// an already fetched batch still publish and commit during drain. ctx governs
	// only the poll loop.
	procCtx := context.WithoutCancel(ctx)

	for {
		fetches := cl.PollFetches(ctx)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(topic string, part int32, err error) {
			c.log.Error("kafka fetch", "topic", topic, "partition", part, "error", err)
		})

		var records []*kgo.Record
		fetches.EachRecord(func(r *kgo.Record) { records = append(records, r) })
		if len(records) == 0 {
			continue
		}
		if c.handleBatch(procCtx, cl, records) {
			if err := cl.CommitRecords(procCtx, records...); err != nil {
				c.log.Error("kafka commit", "error", err)
			}
		}
	}
}

// handleBatch processes every record concurrently (bounded by the pool) and
// reports whether all replies were published. It commits offsets only on a
// clean batch: any publish failure leaves the whole poll uncommitted so the
// records are reprocessed rather than skipped.
func (c *Consumer) handleBatch(ctx context.Context, cl *kgo.Client, records []*kgo.Record) bool {
	var (
		wg sync.WaitGroup
		ok = true
		mu sync.Mutex
	)
	for _, r := range records {
		if !c.sem.Acquire(ctx) {
			return false
		}
		wg.Add(1)
		go func(r *kgo.Record) {
			defer wg.Done()
			defer c.sem.Release()
			if !c.handle(ctx, cl, r) {
				mu.Lock()
				ok = false
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()
	return ok
}

// handle processes one record and produces its reply(ies). It reports success: a
// fire-and-forget record (no reply topic) succeeds immediately; a record with a
// reply topic succeeds only once every reply is acked by the broker. A batch op
// produces one record per item plus a summary, all keyed by the correlation id.
func (c *Consumer) handle(ctx context.Context, cl *kgo.Client, r *kgo.Record) bool {
	replyTopic := c.replyTopicFor(r)
	publish := func(corrID string, reply []byte) error {
		if replyTopic == "" {
			return nil // nowhere to reply — fire-and-forget
		}
		return cl.ProduceSync(ctx, &kgo.Record{
			Topic: replyTopic,
			Key:   []byte(corrID),
			Value: reply,
		}).FirstErr()
	}
	if err := c.proc.Process(ctx, r.Value, string(r.Key), publish); err != nil {
		c.log.Error("kafka produce reply", "error", err, "topic", replyTopic)
		return false
	}
	return true
}

// replyTopicFor resolves where a record's reply goes: a per-record reply-topic
// header overrides the configured default; an empty result means fire-and-forget.
func (c *Consumer) replyTopicFor(r *kgo.Record) string {
	topic := c.cfg.ReplyTopic
	for _, h := range r.Headers {
		if h.Key == replyTopicHeader && len(h.Value) > 0 {
			topic = string(h.Value)
		}
	}
	return topic
}
