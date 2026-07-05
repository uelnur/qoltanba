package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// storeFactory builds a fresh store for the shared suite.
type storeFactory struct {
	name string
	make func(t *testing.T) Store
}

func factories() []storeFactory {
	return []storeFactory{
		{"mem", func(*testing.T) Store { return NewMemStore() }},
		{"bolt", func(t *testing.T) Store {
			s, err := OpenBoltStore(filepath.Join(t.TempDir(), "jobs.db"))
			if err != nil {
				t.Fatalf("OpenBoltStore: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}},
	}
}

func TestStore_CRUD(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			j := &Job{ID: "a1", Op: "sign", Status: StatusQueued, SubmittedAt: time.Unix(1, 0)}

			if err := s.Create(ctx, j); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := s.Create(ctx, j); !errors.Is(err, ErrExists) {
				t.Fatalf("duplicate Create err = %v, want ErrExists", err)
			}
			got, err := s.Get(ctx, "a1")
			if err != nil || got.Op != "sign" {
				t.Fatalf("Get = %+v, err %v", got, err)
			}
			got.Status = StatusSucceeded
			if err := s.Save(ctx, got); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if again, _ := s.Get(ctx, "a1"); again.Status != StatusSucceeded {
				t.Fatalf("status after Save = %s", again.Status)
			}
			if err := s.Delete(ctx, "a1"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := s.Get(ctx, "a1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after Delete err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestStore_RecoverResetsRunning(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			_ = s.Create(ctx, &Job{ID: "run", Op: "sign", Status: StatusRunning, SubmittedAt: time.Unix(1, 0)})
			_ = s.Create(ctx, &Job{ID: "queued", Op: "sign", Status: StatusQueued, SubmittedAt: time.Unix(2, 0)})
			_ = s.Create(ctx, &Job{ID: "done", Op: "sign", Status: StatusSucceeded, SubmittedAt: time.Unix(3, 0)})

			ids, err := s.Recover(ctx)
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if len(ids) != 2 {
				t.Fatalf("recovered %v, want 2 queued (run reset + queued)", ids)
			}
			if got, _ := s.Get(ctx, "run"); got.Status != StatusQueued {
				t.Errorf("running job not reset: %s", got.Status)
			}
		})
	}
}

func TestStore_ReapExpiredTerminal(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			past := time.Unix(100, 0)
			future := time.Unix(10_000, 0)
			_ = s.Create(ctx, &Job{ID: "old", Status: StatusSucceeded, ExpiresAt: &past})
			_ = s.Create(ctx, &Job{ID: "fresh", Status: StatusSucceeded, ExpiresAt: &future})
			_ = s.Create(ctx, &Job{ID: "running", Status: StatusRunning, ExpiresAt: &past}) // not terminal

			n, err := s.Reap(ctx, time.Unix(1000, 0))
			if err != nil {
				t.Fatalf("Reap: %v", err)
			}
			if n != 1 {
				t.Fatalf("reaped %d, want 1", n)
			}
			if _, err := s.Get(ctx, "old"); !errors.Is(err, ErrNotFound) {
				t.Errorf("expired job survived")
			}
			if _, err := s.Get(ctx, "fresh"); err != nil {
				t.Errorf("fresh job reaped")
			}
		})
	}
}

func TestBoltStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.db")
	ctx := context.Background()

	s1, err := OpenBoltStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = s1.Create(ctx, &Job{ID: "p1", Op: "verify", Status: StatusQueued, SubmittedAt: time.Unix(1, 0)})
	_ = s1.Close()

	s2, err := OpenBoltStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, err := s2.Get(ctx, "p1")
	if err != nil || got.Op != "verify" {
		t.Fatalf("persisted job = %+v, err %v", got, err)
	}
}
