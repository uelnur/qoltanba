package mq

import (
	"context"
	"testing"
	"time"
)

func TestSemaphore_BoundsConcurrency(t *testing.T) {
	s := NewSemaphore(2)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if !s.Acquire(ctx) {
			t.Fatalf("acquire %d should succeed", i)
		}
	}
	// Third acquire must block until a slot frees.
	got := make(chan bool, 1)
	go func() { got <- s.Acquire(ctx) }()
	select {
	case <-got:
		t.Fatal("third acquire succeeded while full")
	case <-time.After(20 * time.Millisecond):
	}
	s.Release()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("acquire after release failed")
		}
	case <-time.After(time.Second):
		t.Fatal("acquire did not unblock after release")
	}
}

func TestSemaphore_AcquireCanceled(t *testing.T) {
	s := NewSemaphore(1)
	ctx, cancel := context.WithCancel(context.Background())
	s.Acquire(context.Background()) // fill it
	cancel()
	if s.Acquire(ctx) {
		t.Fatal("acquire on canceled ctx should fail")
	}
}

func TestNewSemaphore_MinOne(t *testing.T) {
	s := NewSemaphore(0)
	if cap(s) != 1 {
		t.Fatalf("cap = %d, want 1", cap(s))
	}
}
