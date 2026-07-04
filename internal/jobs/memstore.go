package jobs

import (
	"context"
	"sync"
	"time"
)

// MemStore is the ephemeral in-memory Store: fast, zero-dependency, the default
// for stateless deployments. Jobs do not survive a restart — Recover always
// starts empty — so a caller that needs durability picks the bbolt store.
type MemStore struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

var _ Store = (*MemStore)(nil)

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{jobs: make(map[string]*Job)} }

func (s *MemStore) Create(_ context.Context, j *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; ok {
		return ErrExists
	}
	s.jobs[j.ID] = cloneJob(j)
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneJob(j), nil
}

func (s *MemStore) Save(_ context.Context, j *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = cloneJob(j)
	return nil
}

func (s *MemStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, id)
	return nil
}

// Recover has nothing durable to restore; an in-memory store is always empty
// after a restart. It still resets any RUNNING jobs to QUEUED for symmetry within
// a single process life (there are none at startup).
func (s *MemStore) Recover(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var queued []string
	for _, j := range s.jobs {
		if j.Status == StatusRunning {
			j.Status = StatusQueued
		}
		if j.Status == StatusQueued {
			queued = append(queued, j.ID)
		}
	}
	return queued, nil
}

func (s *MemStore) Reap(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, j := range s.jobs {
		if j.Status.Terminal() && j.ExpiresAt != nil && !j.ExpiresAt.After(now) {
			delete(s.jobs, id)
			n++
		}
	}
	return n, nil
}

func (s *MemStore) Close() error { return nil }
