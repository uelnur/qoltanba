package native

import (
	"runtime"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// kalkanInstance is what a worker can do with its library instance. The
// abstraction exists for two reasons: the pool does not depend on the cgo type
// directly (DIP), and unit tests swap in a fake to exercise pool mechanics with
// no Kalkan library present. Implemented by *instance (cgo) and by a test fake.
type kalkanInstance interface {
	loadKey(provider.KeyRef) (string, error)
	exportCert(alias string, format int) ([]byte, error)
	certInfo(cert []byte) provider.CertProperties
	signData(alias string, flags int, data, inSign []byte) ([]byte, error)
	verifyData(alias string, flags int, data, sign []byte, inCertID int) verifyOut
	signXML(alias string, flags int, xml []byte, nodeID, parentNode, parentNS string) ([]byte, error)
	verifyXML(alias string, flags int, xml []byte) ([]byte, uint32)
	signWSSE(alias string, flags int, xml []byte, nodeID string) ([]byte, error)
	hashData(algorithm string, flags int, data []byte) ([]byte, error)
	signHash(alias string, flags int, hash []byte) ([]byte, error)
	certFromCMS(cms []byte, sigID, flags int) ([]byte, uint32)
	certFromXML(xml []byte, sigID int) ([]byte, uint32)
	timeFromSig(sig []byte, flags, sigID int) (time.Time, uint32)
	loadCertFile(path string, certType int) error
	validate(cert []byte, validType int, path string, checkTime int64, wantOCSP bool) validateOut
	tsaSetURL(url string)
	has(capID int) bool
	isIsolated() bool
	close()
}

// job is a unit of work run on one instance. The closure receives the worker's
// instance and returns an error; it writes results into the caller's captured
// variables. One job is one atomic operation on one instance (e.g. loadKey and
// signData together), so state never spreads across instances.
type job struct {
	fn   func(inst kalkanInstance) error
	done chan error
}

// worker owns one Kalkan instance and runs its jobs strictly sequentially on a
// pinned OS thread (runtime.LockOSThread). This delivers the model: a worker
// only ever talks to its own Kalkan, always from the same thread (safe even if
// the library uses TLS), and two requests never touch one instance at once.
type worker struct {
	inst kalkanInstance
	jobs <-chan job // shared pool queue (provides load balancing)
	quit <-chan struct{}
}

func (w *worker) run(started chan<- struct{}) {
	// Pin to the OS thread: the worker goroutine does not migrate, so every cgo
	// call to this instance runs from the same thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	close(started)
	for {
		select {
		case j := <-w.jobs:
			j.done <- j.fn(w.inst)
		case <-w.quit:
			w.inst.close()
			return
		}
	}
}
