package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// waitTerminal polls a manager until the job is terminal or the deadline passes.
func waitTerminal(t *testing.T, m *Manager, id string) View {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if v.Status.Terminal() {
			return v
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish in time", id)
	return View{}
}

func allOps(string) bool { return true }

func startManager(t *testing.T, store Store, exec Executor, cfg Config, opts ...Option) *Manager {
	t.Helper()
	m := New(store, exec, allOps, cfg, opts...)
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { cancel(); m.Wait() })
	return m
}

func TestManager_SucceedsAndStoresResult(t *testing.T) {
	exec := func(_ context.Context, op string, req json.RawMessage) (any, error) {
		return map[string]string{"echo": op}, nil
	}
	m := startManager(t, NewMemStore(), exec, Config{Workers: 2})

	v, err := m.Submit(context.Background(), "sign", json.RawMessage(`{"x":1}`), "")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Status != StatusQueued {
		t.Fatalf("submit status = %s, want queued", v.Status)
	}

	got := waitTerminal(t, m, v.ID)
	if got.Status != StatusSucceeded {
		t.Fatalf("status = %s, want succeeded", got.Status)
	}
	raw, status, err := m.Result(context.Background(), v.ID)
	if err != nil || status != StatusSucceeded {
		t.Fatalf("Result err=%v status=%s", err, status)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil || out["echo"] != "sign" {
		t.Fatalf("result = %s, err=%v", raw, err)
	}
}

func TestManager_FailureRecordsError(t *testing.T) {
	exec := func(context.Context, string, json.RawMessage) (any, error) {
		return nil, &core.Error{Kind: core.KindInvalid, Op: "sign"}
	}
	m := startManager(t, NewMemStore(), exec, Config{Workers: 1})

	v, _ := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), "")
	got := waitTerminal(t, m, v.ID)
	if got.Status != StatusFailed || got.Error == nil {
		t.Fatalf("got %+v, want failed with error", got)
	}
	if got.Error.Kind != "invalid" {
		t.Errorf("error kind = %q, want invalid", got.Error.Kind)
	}
}

func TestManager_ResultNotReady(t *testing.T) {
	release := make(chan struct{})
	exec := func(context.Context, string, json.RawMessage) (any, error) {
		<-release
		return "done", nil
	}
	m := startManager(t, NewMemStore(), exec, Config{Workers: 1})
	defer close(release)

	v, _ := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), "")
	_, _, err := m.Result(context.Background(), v.ID)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("Result err = %v, want ErrNotReady", err)
	}
}

func TestManager_Backpressure(t *testing.T) {
	release := make(chan struct{})
	exec := func(context.Context, string, json.RawMessage) (any, error) {
		<-release
		return "ok", nil
	}
	// One worker, queue depth one: the first job occupies the worker, the second
	// fills the queue, the third is rejected.
	m := startManager(t, NewMemStore(), exec, Config{Workers: 1, QueueSize: 1})
	defer close(release)

	if _, err := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), ""); err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	// Give the worker a moment to pick up job 1 so the queue slot is free for job 2.
	time.Sleep(20 * time.Millisecond)
	if _, err := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), ""); err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	_, err := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), "")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("submit 3 err = %v, want ErrBusy", err)
	}
}

func TestManager_CancelQueuedIsNeverExecuted(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	ran := map[string]bool{}
	exec := func(_ context.Context, _ string, req json.RawMessage) (any, error) {
		mu.Lock()
		ran[string(req)] = true
		mu.Unlock()
		if string(req) == `{"hold":true}` {
			<-release
		}
		return "ok", nil
	}
	m := startManager(t, NewMemStore(), exec, Config{Workers: 1})
	defer close(release)

	// Job A holds the single worker; job B stays queued behind it.
	a, _ := m.Submit(context.Background(), "sign", json.RawMessage(`{"hold":true}`), "")
	_ = a
	time.Sleep(20 * time.Millisecond)
	b, _ := m.Submit(context.Background(), "sign", json.RawMessage(`{"b":1}`), "")

	if err := m.Cancel(context.Background(), b.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	got := waitTerminal(t, m, b.ID)
	if got.Status != StatusCanceled {
		t.Fatalf("status = %s, want canceled", got.Status)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran[`{"b":1}`] {
		t.Errorf("canceled job B was executed")
	}
}

func TestManager_Webhook(t *testing.T) {
	done := make(chan View, 1)
	wh := func(_ context.Context, url string, v View) {
		if url == "https://cb.example/hook" {
			done <- v
		}
	}
	exec := func(context.Context, string, json.RawMessage) (any, error) { return "ok", nil }
	m := startManager(t, NewMemStore(), exec, Config{Workers: 1}, WithWebhook(wh))

	v, _ := m.Submit(context.Background(), "sign", json.RawMessage(`{}`), "https://cb.example/hook")
	select {
	case got := <-done:
		if got.ID != v.ID || got.Status != StatusSucceeded {
			t.Fatalf("webhook view = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not delivered")
	}
}

func TestManager_UnknownOpAndTooLarge(t *testing.T) {
	m := New(NewMemStore(), func(context.Context, string, json.RawMessage) (any, error) { return nil, nil },
		func(op string) bool { return op == "sign" }, Config{MaxInputBytes: 8})

	if _, err := m.Submit(context.Background(), "nope", json.RawMessage(`{}`), ""); !errors.Is(err, ErrInvalidOp) {
		t.Errorf("unknown op err = %v, want ErrInvalidOp", err)
	}
	if _, err := m.Submit(context.Background(), "sign", json.RawMessage(`{"data":"toolong"}`), ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized err = %v, want ErrTooLarge", err)
	}
}
