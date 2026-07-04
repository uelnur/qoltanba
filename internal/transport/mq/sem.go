package mq

import "context"

// Semaphore bounds in-flight message processing to the worker-pool size: an MQ
// consumer must not run more concurrent operations than there are driver
// instances, or it would queue work that only serializes at the pool anyway
// while holding message payloads (and thus RAM) in memory. It is a counting
// semaphore over a buffered channel.
type Semaphore chan struct{}

// NewSemaphore builds a Semaphore of capacity n (n<1 is treated as 1).
func NewSemaphore(n int) Semaphore {
	if n < 1 {
		n = 1
	}
	return make(Semaphore, n)
}

// Acquire takes a slot, blocking until one is free or ctx ends. It reports
// whether a slot was acquired (false means ctx was canceled — do not Release).
func (s Semaphore) Acquire(ctx context.Context) bool {
	select {
	case s <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// Release returns a previously acquired slot.
func (s Semaphore) Release() { <-s }
