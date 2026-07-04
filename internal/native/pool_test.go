package native

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// fakeInstance stands in for a real Kalkan instance in unit tests: pool
// mechanics (per-instance serialization, cross-instance parallelism, Close) are
// exercised with no native library. It is instrumented to detect concurrent
// access.
type fakeInstance struct {
	// pool-wide parallelism counters:
	active    *int32
	maxActive *int32
	// per-instance detector of simultaneous access to the SAME instance:
	busy          int32
	sameViolation *int32
	closedCount   *int32
	work          time.Duration
}

func (f *fakeInstance) track() {
	if atomic.AddInt32(&f.busy, 1) != 1 {
		atomic.AddInt32(f.sameViolation, 1) // two requests on one instance at once
	}
	a := atomic.AddInt32(f.active, 1)
	for {
		m := atomic.LoadInt32(f.maxActive)
		if a <= m || atomic.CompareAndSwapInt32(f.maxActive, m, a) {
			break
		}
	}
	time.Sleep(f.work)
	atomic.AddInt32(f.active, -1)
	atomic.AddInt32(&f.busy, -1)
}

func (f *fakeInstance) certInfo(_ []byte) provider.CertProperties {
	f.track()
	return provider.CertProperties{Fields: []provider.CertField{{Name: "SUBJECT_COMMONNAME", Value: "TEST", OK: true}}}
}
func (f *fakeInstance) close()           { atomic.AddInt32(f.closedCount, 1) }
func (f *fakeInstance) has(int) bool     { return true }
func (f *fakeInstance) isIsolated() bool { return true }

// The remaining interface methods are unused in these tests.
func (f *fakeInstance) loadKey(provider.KeyRef) (string, error) { f.track(); return "", nil }
func (f *fakeInstance) exportCert(string, int) ([]byte, error)  { f.track(); return []byte("cert"), nil }
func (f *fakeInstance) signData(string, int, []byte, []byte) ([]byte, error) {
	f.track()
	return []byte("sig"), nil
}
func (f *fakeInstance) signWSSE(string, int, []byte, string) ([]byte, error)  { return nil, nil }
func (f *fakeInstance) hashData(string, int, []byte) ([]byte, error)          { return []byte("h"), nil }
func (f *fakeInstance) signHash(string, int, []byte) ([]byte, error)          { return []byte("sh"), nil }
func (f *fakeInstance) verifyData(string, int, []byte, []byte, int) verifyOut { return verifyOut{} }
func (f *fakeInstance) signXML(string, int, []byte, string, string, string) ([]byte, error) {
	return nil, nil
}
func (f *fakeInstance) verifyXML(string, int, []byte) ([]byte, uint32)        { return nil, 0 }
func (f *fakeInstance) certFromCMS([]byte, int, int) ([]byte, uint32)         { return nil, 0 }
func (f *fakeInstance) certFromXML([]byte, int) ([]byte, uint32)              { return nil, 0 }
func (f *fakeInstance) timeFromSig([]byte, int, int) (time.Time, uint32)      { return time.Time{}, 0 }
func (f *fakeInstance) loadCertFile(string, int) error                        { return nil }
func (f *fakeInstance) validate([]byte, int, string, int64, bool) validateOut { return validateOut{} }
func (f *fakeInstance) tsaSetURL(string)                                      {}

type fakeMetrics struct {
	active, maxActive, sameViolation, closedCount int32
}

func newFakePool(size int, work time.Duration, caps provider.Capabilities) (*Pool, *fakeMetrics) {
	m := &fakeMetrics{}
	insts := make([]kalkanInstance, size)
	for i := range insts {
		insts[i] = &fakeInstance{
			active: &m.active, maxActive: &m.maxActive,
			sameViolation: &m.sameViolation, closedCount: &m.closedCount,
			work: work,
		}
	}
	return newPool(insts, caps), m
}

func hammer(t *testing.T, p *Pool, calls int) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.CertProperties(context.Background(), nil, provider.CertPEM); err != nil {
				t.Errorf("CertProperties: %v", err)
			}
		}()
	}
	wg.Wait()
}

// One instance serializes every operation: parallelism is exactly 1, no violations.
func TestPool_SingleInstanceSerializes(t *testing.T) {
	p, m := newFakePool(1, 3*time.Millisecond, provider.Capabilities{CertInfo: true})
	defer p.Close()
	hammer(t, p, 20)
	if got := atomic.LoadInt32(&m.maxActive); got != 1 {
		t.Fatalf("expected parallelism 1 on a single instance, got %d", got)
	}
	if v := atomic.LoadInt32(&m.sameViolation); v != 0 {
		t.Fatalf("simultaneous access to one instance: %d violations", v)
	}
}

// Several instances run in parallel (up to the pool size), but no single
// instance is used by two requests at once.
func TestPool_MultiInstanceParallelizes(t *testing.T) {
	const size = 4
	p, m := newFakePool(size, 10*time.Millisecond, provider.Capabilities{CertInfo: true})
	defer p.Close()
	hammer(t, p, 40)
	if got := atomic.LoadInt32(&m.maxActive); got < 2 {
		t.Fatalf("expected parallelism >1 across %d instances, got %d", size, got)
	}
	if got := atomic.LoadInt32(&m.maxActive); got > size {
		t.Fatalf("parallelism %d exceeded pool size %d", got, size)
	}
	if v := atomic.LoadInt32(&m.sameViolation); v != 0 {
		t.Fatalf("simultaneous access to one instance: %d violations", v)
	}
}

func TestPool_CloseIdempotentAndRejects(t *testing.T) {
	const size = 3
	p, m := newFakePool(size, time.Millisecond, provider.Capabilities{CertInfo: true})
	hammer(t, p, 10)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil { // idempotent
		t.Fatalf("second Close: %v", err)
	}
	if c := atomic.LoadInt32(&m.closedCount); c != size {
		t.Fatalf("expected %d instances closed, got %d", size, c)
	}
	if _, err := p.CertProperties(context.Background(), nil, provider.CertPEM); !errors.Is(err, provider.ErrClosed) {
		t.Fatalf("expected ErrClosed after Close, got %v", err)
	}
}

func TestPool_UnsupportedWhenCapabilityOff(t *testing.T) {
	p, _ := newFakePool(1, 0, provider.Capabilities{}) // CertInfo=false
	defer p.Close()
	if _, err := p.CertProperties(context.Background(), nil, provider.CertPEM); !errors.Is(err, provider.ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

func TestPool_ContextCancelled(t *testing.T) {
	p, _ := newFakePool(1, 50*time.Millisecond, provider.Capabilities{CertInfo: true})
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled up front
	if _, err := p.CertProperties(ctx, nil, provider.CertPEM); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
