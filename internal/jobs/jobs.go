// Package jobs is the async-job subsystem: it runs an operation off the request
// path so a caller can submit large or slow work, get a jobId and a 202, and
// learn the outcome later by polling, a webhook callback, or MQ delivery. It is
// infrastructure behind a domain-agnostic Executor — it knows nothing about
// crypto; it only schedules op+payload units, tracks their lifecycle and persists
// them through a JobStore whose durability the deployment picks (in-memory or
// on-disk bbolt).
//
// Lifecycle: queued → running → succeeded | failed | canceled. A running job
// cannot resume mid-operation across a restart (a native crypto call is not
// re-entrant), so recovery resets it to queued and re-executes it whole — safe
// because operations are idempotent by input, deduplicated by jobId.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Status is a job's lifecycle state.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceled  Status = "canceled"
)

// Terminal reports whether s is a final state that will not change.
func (s Status) Terminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusCanceled:
		return true
	default:
		return false
	}
}

// Job is the full persisted record. Request and CallbackURL may carry secrets or
// PII and must never be returned to a client — expose View instead. Request is
// scrubbed once the job reaches a terminal state (it is only needed to run or to
// re-run after recovery, neither of which applies to a finished job).
type Job struct {
	ID          string               `json:"id"`
	Op          string               `json:"op"`
	Status      Status               `json:"status"`
	SubmittedAt time.Time            `json:"submittedAt"`
	StartedAt   *time.Time           `json:"startedAt,omitempty"`
	FinishedAt  *time.Time           `json:"finishedAt,omitempty"`
	ExpiresAt   *time.Time           `json:"expiresAt,omitempty"`
	Error       *core.BatchItemError `json:"error,omitempty"`
	Request     json.RawMessage      `json:"request,omitempty"`
	Result      json.RawMessage      `json:"result,omitempty"`
	CallbackURL string               `json:"callbackUrl,omitempty"`
}

// View is the client-safe projection of a Job: identity, lifecycle and timing
// only — never the request payload (secrets/PII) or the callback URL. Every
// transport MUST return this shape from a status endpoint, not the Job itself.
type View struct {
	ID          string               `json:"id"`
	Op          string               `json:"op"`
	Status      Status               `json:"status"`
	SubmittedAt time.Time            `json:"submittedAt"`
	StartedAt   *time.Time           `json:"startedAt,omitempty"`
	FinishedAt  *time.Time           `json:"finishedAt,omitempty"`
	ExpiresAt   *time.Time           `json:"expiresAt,omitempty"`
	Error       *core.BatchItemError `json:"error,omitempty"`
}

// View returns the client-safe projection of j.
func (j *Job) View() View {
	return View{
		ID: j.ID, Op: j.Op, Status: j.Status, SubmittedAt: j.SubmittedAt,
		StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, ExpiresAt: j.ExpiresAt, Error: j.Error,
	}
}

// Store persists jobs. Implementations exist for in-memory (ephemeral) and
// on-disk bbolt (survives a single-node restart). All methods are safe for
// concurrent use.
type Store interface {
	// Create inserts a new job; it errors with ErrExists if the id is taken.
	Create(ctx context.Context, j *Job) error
	// Get returns a copy of the job, or ErrNotFound.
	Get(ctx context.Context, id string) (*Job, error)
	// Save upserts an existing job (a state transition).
	Save(ctx context.Context, j *Job) error
	// Delete removes a job; deleting an absent id is not an error.
	Delete(ctx context.Context, id string) error
	// Recover resets every RUNNING job back to QUEUED (a crashed in-flight job
	// re-runs whole) and returns the ids of all queued jobs to re-enqueue. It runs
	// once at startup.
	Recover(ctx context.Context) ([]string, error)
	// Reap deletes terminal jobs whose ExpiresAt is at or before now, returning
	// how many were removed.
	Reap(ctx context.Context, now time.Time) (int, error)
	// Close releases any resources (e.g. the bbolt file handle).
	Close() error
}

// Sentinel errors from the store and manager.
var (
	ErrNotFound = errors.New("job not found")
	ErrExists   = errors.New("job already exists")
	// ErrBusy means the pending queue is full — the caller should retry later
	// (backpressure). A transport maps it to 503/Unavailable.
	ErrBusy = errors.New("job queue full")
	// ErrTooLarge means the request payload exceeds the configured limit.
	ErrTooLarge = errors.New("job request too large")
	// ErrInvalidOp means the requested operation is not supported.
	ErrInvalidOp = errors.New("unknown operation")
	// ErrNotReady means the result was requested before the job finished.
	ErrNotReady = errors.New("job not finished")
)

// newID returns a random 128-bit hex job id.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// cloneJob returns a deep-enough copy so callers cannot mutate stored state
// through shared slices. Times are value/pointer-copied; the raw messages and
// error are copied by value (RawMessage is an immutable-by-convention []byte).
func cloneJob(j *Job) *Job {
	c := *j
	if j.StartedAt != nil {
		t := *j.StartedAt
		c.StartedAt = &t
	}
	if j.FinishedAt != nil {
		t := *j.FinishedAt
		c.FinishedAt = &t
	}
	if j.ExpiresAt != nil {
		t := *j.ExpiresAt
		c.ExpiresAt = &t
	}
	if j.Error != nil {
		e := *j.Error
		c.Error = &e
	}
	if j.Request != nil {
		c.Request = append(json.RawMessage(nil), j.Request...)
	}
	if j.Result != nil {
		c.Result = append(json.RawMessage(nil), j.Result...)
	}
	return &c
}
