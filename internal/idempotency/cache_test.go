package idempotency

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo_ReplaysCachedSuccess(t *testing.T) {
	c := New(time.Hour, 16, nil)
	var calls int32
	run := func() ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		return []byte("result"), nil
	}

	d1, replayed1, err := c.Do(context.Background(), "k", run)
	if err != nil || replayed1 || string(d1) != "result" {
		t.Fatalf("first: data=%q replayed=%v err=%v", d1, replayed1, err)
	}
	d2, replayed2, err := c.Do(context.Background(), "k", run)
	if err != nil || !replayed2 || string(d2) != "result" {
		t.Fatalf("second: data=%q replayed=%v err=%v", d2, replayed2, err)
	}
	if calls != 1 {
		t.Errorf("fn calls = %d, want 1", calls)
	}
}

func TestDo_EmptyKeyBypasses(t *testing.T) {
	c := New(time.Hour, 16, nil)
	var calls int32
	run := func() ([]byte, error) { atomic.AddInt32(&calls, 1); return []byte("x"), nil }
	for i := 0; i < 3; i++ {
		if _, replayed, _ := c.Do(context.Background(), "", run); replayed {
			t.Fatal("empty key must never replay")
		}
	}
	if calls != 3 {
		t.Errorf("fn calls = %d, want 3", calls)
	}
	if c.Len() != 0 {
		t.Errorf("empty key should not populate the cache, len=%d", c.Len())
	}
}

func TestDo_FailuresNotCached(t *testing.T) {
	c := New(time.Hour, 16, nil)
	var calls int32
	fail := func() ([]byte, error) { atomic.AddInt32(&calls, 1); return nil, errors.New("boom") }

	if _, _, err := c.Do(context.Background(), "k", fail); err == nil {
		t.Fatal("expected error")
	}
	// A retry after a failure must re-execute (not replay the error).
	ok := func() ([]byte, error) { atomic.AddInt32(&calls, 1); return []byte("recovered"), nil }
	d, replayed, err := c.Do(context.Background(), "k", ok)
	if err != nil || replayed || string(d) != "recovered" {
		t.Fatalf("retry: data=%q replayed=%v err=%v", d, replayed, err)
	}
	if calls != 2 {
		t.Errorf("fn calls = %d, want 2", calls)
	}
}

func TestDo_SingleFlightCoalesces(t *testing.T) {
	c := New(time.Hour, 16, nil)
	var calls int32
	release := make(chan struct{})
	started := make(chan struct{})
	run := func() ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		close(started)
		<-release // hold the in-flight call open
		return []byte("shared"), nil
	}

	const n = 8
	var wg sync.WaitGroup
	results := make([][]byte, n)
	// Launch the first call; wait until it's in-flight, then the rest coalesce.
	wg.Add(1)
	go func() { defer wg.Done(); results[0], _, _ = c.Do(context.Background(), "k", run) }()
	<-started
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _, _ = c.Do(context.Background(), "k", run)
		}(i)
	}
	// Give the coalescing goroutines a moment to block on the in-flight entry.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if calls != 1 {
		t.Errorf("fn calls = %d, want 1 (single-flight)", calls)
	}
	for i, r := range results {
		if string(r) != "shared" {
			t.Errorf("result[%d] = %q, want shared", i, r)
		}
	}
}

func TestDo_TTLExpiry(t *testing.T) {
	nowT := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return nowT }
	c := New(time.Minute, 16, clock)
	var calls int32
	run := func() ([]byte, error) { atomic.AddInt32(&calls, 1); return []byte("v"), nil }

	c.Do(context.Background(), "k", run)
	nowT = nowT.Add(2 * time.Minute) // past the TTL
	if _, replayed, _ := c.Do(context.Background(), "k", run); replayed {
		t.Error("expired entry must not replay")
	}
	if calls != 2 {
		t.Errorf("fn calls = %d, want 2", calls)
	}
}

func TestDo_LRUEviction(t *testing.T) {
	c := New(time.Hour, 2, nil) // capacity 2
	run := func(v string) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(v), nil }
	}
	c.Do(context.Background(), "a", run("a"))
	c.Do(context.Background(), "b", run("b"))
	c.Do(context.Background(), "c", run("c")) // evicts "a" (LRU)

	if c.Len() != 2 {
		t.Fatalf("len = %d, want 2", c.Len())
	}
	var reran int32
	rerun := func() ([]byte, error) { atomic.AddInt32(&reran, 1); return []byte("a2"), nil }
	if _, replayed, _ := c.Do(context.Background(), "a", rerun); replayed {
		t.Error("evicted key should re-run, not replay")
	}
	if reran != 1 {
		t.Errorf("evicted key reran %d times, want 1", reran)
	}
}
