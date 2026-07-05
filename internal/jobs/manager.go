package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Executor runs one operation. It is the domain-agnostic seam between the job
// scheduler and the crypto service: main injects a closure over the shared
// operation router, so the jobs package never imports a transport or the domain
// service directly. The returned value is the operation output (marshaled to the
// job Result); the error is rendered into the job Error.
type Executor func(ctx context.Context, op string, request json.RawMessage) (any, error)

// OpValidator reports whether op is a supported operation (injected from the
// same router, so the job contract and the sync contract cannot drift).
type OpValidator func(op string) bool

// Webhook delivers a terminal job notification to a caller-supplied URL. It gets
// the client-safe View only (never the request or result payload). It is
// best-effort and must not block the worker for long — nil disables callbacks.
type Webhook func(ctx context.Context, url string, v View)

// Config tunes the job manager. Zero values fall back to safe defaults.
type Config struct {
	Workers       int           // concurrent job executors (default 1)
	QueueSize     int           // pending queue depth before backpressure (default 128)
	TTL           time.Duration // retention for terminal jobs (default 1h)
	MaxInputBytes int           // reject larger request payloads (0 = unlimited)
	ReapInterval  time.Duration // sweep cadence for expired jobs (default min(TTL, 5m))
}

func (c Config) withDefaults() Config {
	if c.Workers < 1 {
		c.Workers = 1
	}
	if c.QueueSize < 1 {
		c.QueueSize = 128
	}
	if c.TTL <= 0 {
		c.TTL = time.Hour
	}
	if c.ReapInterval <= 0 {
		c.ReapInterval = c.TTL
		if c.ReapInterval > 5*time.Minute {
			c.ReapInterval = 5 * time.Minute
		}
	}
	return c
}

// Manager schedules jobs over a bounded worker pool and persists their lifecycle
// through a Store. It owns no crypto — it runs whatever the injected Executor
// does — so it is tested without Kalkan.
type Manager struct {
	store   Store
	exec    Executor
	validOp OpValidator
	webhook Webhook
	cfg     Config
	log     *slog.Logger
	now     func() time.Time

	queue   chan string
	cancels sync.Map // job id -> context.CancelFunc for a running job
	wg      sync.WaitGroup

	baseCtx context.Context
	started sync.Once
}

// Option configures a Manager.
type Option func(*Manager)

// WithWebhook sets the terminal-notification delivery function.
func WithWebhook(w Webhook) Option { return func(m *Manager) { m.webhook = w } }

// WithLogger sets the structured logger (nil-safe: a discarding logger is used).
func WithLogger(l *slog.Logger) Option { return func(m *Manager) { m.log = l } }

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// New builds a Manager. store persists jobs; exec runs them; validOp gates the
// operation name at submit time.
func New(store Store, exec Executor, validOp OpValidator, cfg Config, opts ...Option) *Manager {
	m := &Manager{
		store:   store,
		exec:    exec,
		validOp: validOp,
		cfg:     cfg.withDefaults(),
		log:     slog.Default(),
		now:     time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	m.queue = make(chan string, m.cfg.QueueSize)
	return m
}

// Start recovers persisted jobs, launches the worker pool and the TTL reaper.
// The pool drains and every goroutine returns when ctx is canceled; call Wait
// afterwards to block until they finish. Start is idempotent.
func (m *Manager) Start(ctx context.Context) error {
	var startErr error
	m.started.Do(func() {
		m.baseCtx = ctx
		recovered, err := m.store.Recover(ctx)
		if err != nil {
			startErr = err
			return
		}
		for i := 0; i < m.cfg.Workers; i++ {
			m.wg.Add(1)
			go m.worker(ctx)
		}
		m.wg.Add(1)
		go m.reaper(ctx)
		// Feed recovered jobs through the queue without blocking Start; workers
		// drain them as capacity frees.
		if len(recovered) > 0 {
			m.wg.Add(1)
			go m.requeue(ctx, recovered)
		}
		m.log.Info("job manager started", "workers", m.cfg.Workers, "queueSize", m.cfg.QueueSize,
			"recovered", len(recovered))
	})
	return startErr
}

// Wait blocks until every worker and helper goroutine has returned (after ctx,
// passed to Start, is canceled).
func (m *Manager) Wait() { m.wg.Wait() }

// Close releases the underlying store; call it after Wait during shutdown.
func (m *Manager) Close() error { return m.store.Close() }

// Submit validates and enqueues a job, returning its client-safe view. It never
// blocks: a full queue returns ErrBusy (backpressure). callbackURL is optional.
func (m *Manager) Submit(ctx context.Context, op string, request json.RawMessage, callbackURL string) (View, error) {
	if !m.validOp(op) {
		return View{}, ErrInvalidOp
	}
	if m.cfg.MaxInputBytes > 0 && len(request) > m.cfg.MaxInputBytes {
		return View{}, ErrTooLarge
	}
	j := &Job{
		ID:          newID(),
		Op:          op,
		Status:      StatusQueued,
		SubmittedAt: m.now(),
		Request:     append(json.RawMessage(nil), request...),
		CallbackURL: callbackURL,
	}
	if err := m.store.Create(ctx, j); err != nil {
		return View{}, err
	}
	select {
	case m.queue <- j.ID:
		return j.View(), nil
	default:
		// Roll back the record so a rejected submit leaves nothing behind.
		_ = m.store.Delete(ctx, j.ID)
		return View{}, ErrBusy
	}
}

// Get returns the client-safe view of a job, or ErrNotFound.
func (m *Manager) Get(ctx context.Context, id string) (View, error) {
	j, err := m.store.Get(ctx, id)
	if err != nil {
		return View{}, err
	}
	return j.View(), nil
}

// Result returns a finished job's marshaled output. It reports ErrNotReady while
// the job is still queued/running, and returns the job status so a caller can
// distinguish success from a failed/canceled job (whose Result is empty).
func (m *Manager) Result(ctx context.Context, id string) (json.RawMessage, Status, error) {
	j, err := m.store.Get(ctx, id)
	if err != nil {
		return nil, "", err
	}
	if !j.Status.Terminal() {
		return nil, j.Status, ErrNotReady
	}
	return j.Result, j.Status, nil
}

// Cancel stops a job: a queued job is marked canceled (a worker will skip it), a
// running job additionally has its context canceled (best-effort — a native
// crypto call already in flight cannot be interrupted). A terminal job is left
// unchanged (idempotent).
func (m *Manager) Cancel(ctx context.Context, id string) error {
	j, err := m.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if j.Status.Terminal() {
		return nil
	}
	if c, ok := m.cancels.Load(id); ok {
		c.(context.CancelFunc)()
	}
	now := m.now()
	j.Status = StatusCanceled
	j.FinishedAt = &now
	j.Request = nil // scrub the payload once terminal
	m.setExpiry(j, now)
	if err := m.store.Save(ctx, j); err != nil {
		return err
	}
	base := m.baseCtx
	if base == nil {
		base = context.Background()
	}
	//nolint:contextcheck // a cancel notification must outlive the request that triggers it; baseCtx is the service lifetime
	m.fireWebhook(base, j)
	return nil
}

// worker consumes job ids and executes each one.
func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.queue:
			m.run(ctx, id)
		}
	}
}

// run executes one job by id, driving its state transitions and persistence.
func (m *Manager) run(ctx context.Context, id string) {
	j, err := m.store.Get(ctx, id)
	if err != nil {
		return // reaped or canceled+deleted before pickup
	}
	if j.Status != StatusQueued {
		return // canceled while queued, or already handled
	}

	start := m.now()
	j.Status = StatusRunning
	j.StartedAt = &start
	if err := m.store.Save(ctx, j); err != nil {
		m.log.Warn("job persist running failed", "job", id, "error", err)
	}

	jobCtx, cancel := context.WithCancel(ctx)
	m.cancels.Store(id, cancel)
	out, execErr := m.exec(jobCtx, j.Op, j.Request)
	m.cancels.Delete(id)
	cancel()

	// A canceled context is either a user Cancel (already recorded terminal) or a
	// service shutdown: in neither case do we overwrite the job with a failure —
	// on shutdown it stays RUNNING and re-runs after restart recovery.
	if execErr != nil && errors.Is(execErr, context.Canceled) {
		if cur, gerr := m.store.Get(ctx, id); gerr == nil && cur.Status == StatusCanceled {
			return
		}
		m.log.Info("job interrupted, will re-run after restart", "job", id)
		return
	}

	fin := m.now()
	j.FinishedAt = &fin
	j.Request = nil // scrub the payload once terminal
	m.setExpiry(j, fin)
	if execErr != nil {
		j.Status = StatusFailed
		j.Error = errorView(execErr)
	} else {
		j.Status = StatusSucceeded
		if raw, merr := json.Marshal(out); merr == nil {
			j.Result = raw
		} else {
			j.Status = StatusFailed
			j.Error = &core.BatchItemError{Kind: core.KindName(core.KindInternal), Message: "encode result"}
		}
	}
	if err := m.store.Save(ctx, j); err != nil {
		m.log.Warn("job persist terminal failed", "job", id, "status", j.Status, "error", err)
	}
	m.fireWebhook(ctx, j)
}

// reaper periodically deletes expired terminal jobs.
func (m *Manager) reaper(ctx context.Context) {
	defer m.wg.Done()
	t := time.NewTicker(m.cfg.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := m.store.Reap(ctx, m.now()); err != nil {
				m.log.Warn("job reap failed", "error", err)
			} else if n > 0 {
				m.log.Debug("reaped expired jobs", "count", n)
			}
		}
	}
}

// requeue feeds recovered job ids into the queue, respecting ctx cancellation.
func (m *Manager) requeue(ctx context.Context, ids []string) {
	defer m.wg.Done()
	for _, id := range ids {
		select {
		case <-ctx.Done():
			return
		case m.queue <- id:
		}
	}
}

// setExpiry stamps ExpiresAt from the TTL (0 TTL keeps jobs until process exit).
func (m *Manager) setExpiry(j *Job, from time.Time) {
	if m.cfg.TTL > 0 {
		exp := from.Add(m.cfg.TTL)
		j.ExpiresAt = &exp
	}
}

// fireWebhook delivers a terminal notification off the worker path, bounded by a
// short timeout derived from base (the caller passes the service-lifetime context
// so the delivery outlives the job/request but stops on shutdown). Best-effort.
func (m *Manager) fireWebhook(base context.Context, j *Job) {
	if m.webhook == nil || j.CallbackURL == "" {
		return
	}
	url, v := j.CallbackURL, j.View()
	go func() {
		ctx, cancel := context.WithTimeout(base, 10*time.Second)
		defer cancel()
		m.webhook(ctx, url, v)
	}()
}

// errorView renders an execution error into the client-safe error envelope,
// reusing the domain's rendering so a job error reads like a sync error.
func errorView(err error) *core.BatchItemError {
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
	return &core.BatchItemError{Kind: core.KindName(kind), Code: exp.Code, Message: msg, Action: exp.Action}
}
