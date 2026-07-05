//go:build qoltanba_functional

package native

import (
	"context"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// TestFunctional_ConcurrentSameInstance loads a size-1 pool with many parallel
// requests, all serialized on the single instance. It checks correctness under
// concurrency even without isolation.
func TestFunctional_ConcurrentSameInstance(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	runConcurrent(t, p, 24)
}

// TestFunctional_PoolIsolation is the key check of the "each worker its own
// Kalkan" model: it brings up an isolated pool and runs parallel sign+verify on
// different instances at once. If isolation cannot be achieved on the real
// library, Open returns an error and we see it.
func TestFunctional_PoolIsolation(t *testing.T) {
	size := envInt("QOLTANBA_POOL", 4)
	if size < 2 {
		size = 4
	}
	p := openPool(t, size, true)
	defer p.Close()
	if !p.Isolated() {
		t.Fatalf("isolation not achieved at pool size %d", size)
	}
	t.Logf("isolated pool up: size=%d", p.Capabilities().PoolSize)
	runConcurrent(t, p, size*10)
}

func runConcurrent(t *testing.T, p *Pool, calls int) {
	t.Helper()
	ctx := context.Background()
	key := envKey()
	var wg sync.WaitGroup
	errCh := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := p.SignCMS(ctx, provider.SignRequest{Key: key, Data: testData, OutPEM: true})
			if err != nil {
				errCh <- err
				return
			}
			res, err := p.VerifyCMS(ctx, provider.VerifyRequest{Signature: sig.Signature, InputPEM: true})
			if err != nil {
				errCh <- err
				return
			}
			if !res.Valid {
				errCh <- &nonFatal{"signature invalid under concurrency"}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	n := 0
	for err := range errCh {
		n++
		if n <= 5 {
			t.Errorf("concurrent operation: %v", err)
		}
	}
	if n > 0 {
		t.Fatalf("%d/%d operations failed under concurrency", n, calls)
	}
	t.Logf("%d concurrent sign+verify succeeded", calls)
}

type nonFatal struct{ s string }

func (e *nonFatal) Error() string { return e.s }

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
