// Package idempotency gives at-most-once execution keyed by a caller-supplied
// idempotency key: the first call for a key runs the work and caches its result;
// a retry within the TTL replays that result instead of re-executing — so a
// redelivered message or a double-clicked request does not produce a duplicate
// signature or a doubled job. Concurrent duplicates coalesce (single-flight): a
// second caller waits for and receives the first's result rather than racing it.
//
// Scope is deliberately node-local and in-memory: it protects against a client or
// broker re-sending (HTTP retry, MQ at-least-once redelivery), not against a race
// across multiple service instances — that would need a shared store and is out
// of scope here. Only successful results are cached; a failed call is dropped so a
// genuine retry can still succeed.
package idempotency

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

// entry is one cached (or in-flight) call. done is closed when the call finishes;
// data/err carry its outcome; expiry is set on success (zero while in-flight).
type entry struct {
	key    string
	done   chan struct{}
	data   []byte
	err    error
	expiry time.Time
}

// Cache is a bounded, TTL'd, single-flight idempotency cache. Safe for concurrent
// use.
type Cache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	byKey map[string]*list.Element // key -> element whose Value is *entry
	lru   *list.List               // front = most recently used
}

// New builds a Cache retaining a successful result for ttl and holding at most max
// entries (LRU eviction beyond that). now defaults to time.Now; max floors at 1.
func New(ttl time.Duration, max int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	if max < 1 {
		max = 1024
	}
	return &Cache{ttl: ttl, max: max, now: now, byKey: make(map[string]*list.Element), lru: list.New()}
}

// Do runs fn at most once per key within the TTL. A retry — or a coalesced
// concurrent call — with the same key replays the first result instead of running
// fn again, and replayed reports that. Only successful results are cached: if fn
// errors, the entry is dropped so a later retry re-executes. An empty key bypasses
// the cache entirely (fn always runs). A panic in fn is converted to an error and
// never cached.
func (c *Cache) Do(ctx context.Context, key string, fn func() ([]byte, error)) (data []byte, replayed bool, err error) {
	if key == "" {
		d, e := runGuarded(fn)
		return d, false, e
	}

	c.mu.Lock()
	if el, ok := c.byKey[key]; ok {
		e := el.Value.(*entry)
		select {
		case <-e.done:
			// Completed. A present done-entry is always a success (failures are
			// dropped), cached until expiry.
			if e.expiry.IsZero() || c.now().Before(e.expiry) {
				c.lru.MoveToFront(el)
				c.mu.Unlock()
				return e.data, true, nil
			}
			c.removeLocked(el) // expired → drop and re-run below
		default:
			// In-flight: coalesce onto the running call, waiting outside the lock.
			c.mu.Unlock()
			select {
			case <-e.done:
				return e.data, true, e.err
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
		}
	}

	// Register an in-flight entry, then run fn without holding the lock.
	e := &entry{key: key, done: make(chan struct{})}
	el := c.lru.PushFront(e)
	c.byKey[key] = el
	c.evictLocked()
	c.mu.Unlock()

	data, err = runGuarded(fn)

	c.mu.Lock()
	if err != nil {
		e.err = err
		if cur, ok := c.byKey[key]; ok && cur == el {
			c.removeLocked(el) // never cache a failure
		}
		c.mu.Unlock()
		close(e.done)
		return nil, false, err
	}
	e.data = data
	e.expiry = c.now().Add(c.ttl)
	c.mu.Unlock()
	close(e.done)
	return data, false, nil
}

// Len returns the number of tracked entries (for tests/metrics).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// removeLocked drops el from both indexes. Caller holds the lock.
func (c *Cache) removeLocked(el *list.Element) {
	e := el.Value.(*entry)
	delete(c.byKey, e.key)
	c.lru.Remove(el)
}

// evictLocked trims the least-recently-used entries down to the max. Caller holds
// the lock.
func (c *Cache) evictLocked() {
	for c.lru.Len() > c.max {
		if back := c.lru.Back(); back != nil {
			c.removeLocked(back)
		} else {
			return
		}
	}
}

// runGuarded runs fn, converting a panic into an error so a panicking call cannot
// leave a permanently in-flight entry deadlocking waiters.
func runGuarded(fn func() ([]byte, error)) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("idempotency: work panicked: %v", r)
		}
	}()
	return fn()
}
