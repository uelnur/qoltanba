package cryptoworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Defaults for an unset Config field.
const (
	defaultCallTimeout = 60 * time.Second
	defaultMaxOps      = 1000
	defaultMaxRSSBytes = 512 << 20
	// rssCheckEvery bounds how often a child's memory is read from /proc: often
	// enough to catch the ~1 MB-per-verification leak long before it matters,
	// rarely enough not to add a file read to every call.
	rssCheckEvery = 16
	// warmRetryDelay paces retries when a standby child cannot be started, so a
	// broken environment does not become a spawn loop.
	warmRetryDelay = 2 * time.Second
)

// errCallTimeout is returned when a child does not answer in time. The native
// calls have no timeout of their own, so killing the child is the only way a
// hung responder or a stuck library call ends.
var errCallTimeout = errors.New("cryptoworker: call timed out")

// Config parameterizes the pool of child processes.
type Config struct {
	// Command is the argv that starts one child; it must run this binary's
	// crypto-worker subcommand.
	Command []string
	// Env is the child environment. Nil inherits the parent's.
	Env []string
	// Size is the number of children, i.e. how many crypto operations can run at
	// once. Values below 1 become 1.
	Size int
	// CallTimeout bounds one operation. Zero uses defaultCallTimeout.
	CallTimeout time.Duration
	// MaxOps retires a child after this many operations. Zero uses defaultMaxOps;
	// a negative value disables the op budget.
	MaxOps int
	// MaxRSSBytes retires a child once its resident memory reaches this size —
	// the direct answer to the library's per-operation leak. Zero uses
	// defaultMaxRSSBytes; a negative value disables the memory budget. Requires
	// /proc (Linux); elsewhere only the op budget applies.
	MaxRSSBytes int64
	// Standby is how many pre-warmed children are kept ready to take over from a
	// retired one. Recycling is routine (it is what discards the library's leak),
	// and starting a child costs a library load, so a warm spare removes that cost
	// from the request path. Zero starts the replacement on demand instead, which
	// is cheaper in memory: each spare holds its own loaded library.
	Standby int
	// KeepAfterRevoked disables retiring a child that returned a revoked verdict,
	// which is the known trigger of the library's memory corruption. Diagnostics
	// only.
	KeepAfterRevoked bool
	// Stderr receives child diagnostics. Nil uses the parent's stderr.
	Stderr io.Writer
	// Log receives supervisor events (crash, recycle). Nil disables them.
	Log *slog.Logger
}

func (c Config) size() int {
	if c.Size < 1 {
		return 1
	}
	return c.Size
}

func (c Config) callTimeout() time.Duration {
	if c.CallTimeout <= 0 {
		return defaultCallTimeout
	}
	return c.CallTimeout
}

func (c Config) maxOps() int {
	if c.MaxOps == 0 {
		return defaultMaxOps
	}
	return c.MaxOps
}

func (c Config) standby() int {
	if c.Standby < 0 {
		return 0
	}
	return c.Standby
}

func (c Config) maxRSS() int64 {
	if c.MaxRSSBytes == 0 {
		return defaultMaxRSSBytes
	}
	return c.MaxRSSBytes
}

// Stats counts supervisor events for observability.
type Stats struct {
	Spawns   uint64 // children started
	Crashes  uint64 // children that died mid-call
	Recycles uint64 // children retired deliberately
	Timeouts uint64 // calls that exceeded CallTimeout
	HotSwaps uint64 // replacements served from the warm standby instead of a cold start
}

// slot is one concurrency unit: it owns at most one live child. A slot with no
// child spawns one on next use, so a retired child costs nothing until the next
// call arrives.
type slot struct {
	proc *process
	ops  int
}

// Supervisor owns the child processes and implements the provider port over
// them. It is the only Provider the service uses: the parent process never loads
// the library, so neither the leak nor the corruption can accumulate in it.
type Supervisor struct {
	cfg  Config
	free chan *slot
	caps provider.Capabilities

	// standby holds pre-warmed children; warmRequest wakes the warmer to refill
	// it, and stop ends the warmer at Close.
	standby     chan *process
	warmRequest chan struct{}
	stop        chan struct{}
	warmerDone  sync.WaitGroup

	mu     sync.Mutex
	closed bool

	inUse                                         atomic.Int64
	spawns, crashes, recycles, timeouts, hotSwaps atomic.Uint64
}

// Start brings up the supervisor and reads the library's capabilities from a
// first child, so a broken setup (missing binary, unloadable library) surfaces at
// startup rather than on the first request. The remaining children start on
// demand.
func Start(cfg Config) (*Supervisor, error) {
	if len(cfg.Command) == 0 {
		return nil, errors.New("cryptoworker: Command not set")
	}
	s := &Supervisor{
		cfg:         cfg,
		free:        make(chan *slot, cfg.size()),
		standby:     make(chan *process, cfg.standby()),
		warmRequest: make(chan struct{}, 1),
		stop:        make(chan struct{}),
	}
	first := &slot{}
	p, err := s.spawn()
	if err != nil {
		return nil, err
	}
	first.proc = p
	s.free <- first
	for i := 1; i < cfg.size(); i++ {
		s.free <- &slot{}
	}
	caps, err := call[struct{}, provider.Capabilities](s, context.Background(), opCapabilities, struct{}{})
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("cryptoworker: read capabilities: %w", err)
	}
	s.caps = caps
	if cfg.standby() > 0 {
		s.warmerDone.Add(1)
		go s.warmLoop()
		s.requestWarm()
	}
	return s, nil
}

// warmLoop keeps the standby set filled. It runs in the background so a request
// never waits for a library load, and it backs off on failure so a broken
// environment does not turn into a spawn loop.
func (s *Supervisor) warmLoop() {
	defer s.warmerDone.Done()
	for {
		select {
		case <-s.stop:
			return
		case <-s.warmRequest:
			for len(s.standby) < cap(s.standby) {
				p, err := s.spawn()
				if err != nil {
					s.logf(context.Background(), slog.LevelWarn, "cannot pre-warm a crypto worker", "error", err)
					if !s.sleep(warmRetryDelay) {
						return
					}
					break
				}
				select {
				case s.standby <- p:
				case <-s.stop:
					p.kill()
					return
				}
			}
		}
	}
}

// sleep waits for d, reporting false if the supervisor closed meanwhile.
func (s *Supervisor) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.stop:
		return false
	}
}

func (s *Supervisor) requestWarm() {
	select {
	case s.warmRequest <- struct{}{}:
	default: // a refill is already pending
	}
}

// takeStandby hands over a pre-warmed child if one is ready, and asks the warmer
// to replace it. It never blocks: with no spare ready the caller starts one.
func (s *Supervisor) takeStandby() *process {
	select {
	case p := <-s.standby:
		s.hotSwaps.Add(1)
		s.requestWarm()
		return p
	default:
		return nil
	}
}

// Capabilities reports what the library in the children supports. It is read once
// at startup: every child loads the same library.
func (s *Supervisor) Capabilities() provider.Capabilities { return s.caps }

// SelfTest runs the driver's smoke check in a child.
func (s *Supervisor) SelfTest(ctx context.Context) (provider.SelfTestResult, error) {
	return call[struct{}, provider.SelfTestResult](s, ctx, opSelfTest, struct{}{})
}

func (s *Supervisor) SignCMS(ctx context.Context, req provider.SignRequest) (provider.SignResult, error) {
	return call[provider.SignRequest, provider.SignResult](s, ctx, opSignCMS, req)
}

func (s *Supervisor) VerifyCMS(ctx context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	return call[provider.VerifyRequest, provider.VerifyResult](s, ctx, opVerifyCMS, req)
}

func (s *Supervisor) SignXML(ctx context.Context, req provider.SignXMLRequest) (provider.SignResult, error) {
	return call[provider.SignXMLRequest, provider.SignResult](s, ctx, opSignXML, req)
}

func (s *Supervisor) VerifyXML(ctx context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	return call[provider.VerifyRequest, provider.VerifyResult](s, ctx, opVerifyXML, req)
}

func (s *Supervisor) SignWSSE(ctx context.Context, req provider.SignWSSERequest) (provider.SignResult, error) {
	return call[provider.SignWSSERequest, provider.SignResult](s, ctx, opSignWSSE, req)
}

func (s *Supervisor) ExportOwnerCert(ctx context.Context, key provider.KeyRef, format provider.CertFormat) (provider.ExportResult, error) {
	return call[exportRequest, provider.ExportResult](s, ctx, opExportCert, exportRequest{Key: key, Format: format})
}

func (s *Supervisor) CertProperties(ctx context.Context, cert []byte, format provider.CertFormat) (provider.CertProperties, error) {
	return call[certPropsRequest, provider.CertProperties](s, ctx, opCertProps, certPropsRequest{Cert: cert, Format: format})
}

func (s *Supervisor) ValidateCert(ctx context.Context, req provider.ValidateRequest) (provider.ValidateResult, error) {
	return call[provider.ValidateRequest, provider.ValidateResult](s, ctx, opValidateCert, req)
}

func (s *Supervisor) Hash(ctx context.Context, req provider.HashRequest) (provider.HashResult, error) {
	return call[provider.HashRequest, provider.HashResult](s, ctx, opHash, req)
}

func (s *Supervisor) SignHash(ctx context.Context, req provider.SignHashRequest) (provider.SignResult, error) {
	return call[provider.SignHashRequest, provider.SignResult](s, ctx, opSignHash, req)
}

// PoolStats mirrors the driver pool's utilization view (in-use, size) so the
// existing pool metric keeps working when the children hold the library.
func (s *Supervisor) PoolStats() (inUse, size int) {
	return int(s.inUse.Load()), s.cfg.size()
}

// WorkerStats returns the child-process lifecycle counters.
func (s *Supervisor) WorkerStats() Stats {
	return Stats{
		Spawns:   s.spawns.Load(),
		Crashes:  s.crashes.Load(),
		Recycles: s.recycles.Load(),
		Timeouts: s.timeouts.Load(),
		HotSwaps: s.hotSwaps.Load(),
	}
}

// Close stops every child. It waits for in-flight calls to return their slots
// first, so a shutdown does not sever a call that is about to answer.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	// Stop the warmer before draining, or it could spawn a child after the last
	// one is killed.
	close(s.stop)
	s.warmerDone.Wait()

	for i := 0; i < s.cfg.size(); i++ {
		sl := <-s.free
		s.retire(sl)
	}
	for {
		select {
		case p := <-s.standby:
			p.kill()
		default:
			return nil
		}
	}
}

// call runs one operation in a child. A child that dies mid-call is the failure
// this package exists for, so the call is retried once on a fresh child. Every
// port operation is safe to repeat: they compute over their inputs and mutate no
// state the caller can observe.
func call[In, Out any](s *Supervisor, ctx context.Context, op string, in In) (Out, error) {
	var zero Out
	payload, err := json.Marshal(in)
	if err != nil {
		return zero, fmt.Errorf("cryptoworker: encode %s: %w", op, err)
	}
	req := request{Op: op, Payload: payload}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		out, err, retryable := callOnce[Out](s, ctx, req)
		if err == nil || !retryable {
			return out, err
		}
		lastErr = err
		s.logf(ctx, slog.LevelWarn, "crypto worker lost, retrying on a fresh child",
			"op", op, "error", err, "attempt", attempt+1)
	}
	return zero, lastErr
}

// callOnce acquires a slot, runs one operation and decides the child's fate. The
// bool reports whether the error is worth retrying on another child.
func callOnce[Out any](s *Supervisor, ctx context.Context, req request) (Out, error, bool) {
	var zero Out
	sl, err := s.acquire(ctx)
	if err != nil {
		return zero, err, false
	}
	s.inUse.Add(1)
	defer func() {
		s.inUse.Add(-1)
		s.free <- sl
	}()

	if sl.proc == nil {
		p := s.takeStandby()
		if p == nil {
			var err error
			if p, err = s.spawn(); err != nil {
				return zero, err, false
			}
		}
		sl.proc, sl.ops = p, 0
	}

	resp, err := sl.proc.call(ctx, req, s.cfg.callTimeout())
	if err != nil {
		// The stream is no longer trustworthy whatever went wrong (crash, timeout,
		// cancellation mid-frame), so the child is retired either way.
		s.retire(sl)
		switch {
		case errors.Is(err, errCallTimeout):
			s.timeouts.Add(1)
			return zero, err, false
		case ctx.Err() != nil:
			return zero, ctx.Err(), false
		default:
			s.crashes.Add(1)
			return zero, err, true
		}
	}
	sl.ops++

	var out Out
	if len(resp.Payload) > 0 {
		if derr := json.Unmarshal(resp.Payload, &out); derr != nil {
			s.retire(sl)
			return zero, fmt.Errorf("cryptoworker: decode %s result: %w", req.Op, derr), false
		}
	}
	if reason := s.recycleReason(sl, resp.Revoked); reason != "" {
		s.recycles.Add(1)
		s.logf(ctx, slog.LevelInfo, "recycling crypto worker", "reason", reason, "ops", sl.ops)
		s.retire(sl)
	}
	return out, resp.Err.decode(), false
}

// recycleReason reports why the child that just answered should be retired, or ""
// to keep it. The memory budget is what bounds the library's per-operation leak;
// the op budget bounds anything the memory reading cannot see; a revoked verdict
// is the known corruption trigger.
func (s *Supervisor) recycleReason(sl *slot, revoked bool) string {
	if revoked && !s.cfg.KeepAfterRevoked {
		return "revoked verdict"
	}
	if max := s.cfg.maxOps(); max > 0 && sl.ops >= max {
		return "op budget"
	}
	if max := s.cfg.maxRSS(); max > 0 && sl.ops%rssCheckEvery == 0 {
		if rss, ok := processRSSBytes(sl.proc.cmd.Process.Pid); ok && rss >= max {
			return fmt.Sprintf("memory budget (%d MB)", rss>>20)
		}
	}
	return ""
}

func (s *Supervisor) acquire(ctx context.Context) (*slot, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, provider.ErrClosed
	}
	select {
	case sl := <-s.free:
		return sl, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Supervisor) retire(sl *slot) {
	if sl.proc != nil {
		sl.proc.kill()
		sl.proc = nil
	}
	sl.ops = 0
	if s.cfg.standby() > 0 {
		s.requestWarm()
	}
}

func (s *Supervisor) spawn() (*process, error) {
	p, err := startProcess(s.cfg)
	if err != nil {
		return nil, err
	}
	s.spawns.Add(1)
	return p, nil
}

func (s *Supervisor) logf(ctx context.Context, level slog.Level, msg string, args ...any) {
	if s.cfg.Log == nil {
		return
	}
	s.cfg.Log.Log(ctx, level, msg, args...)
}

// process is one child and its pipes.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func startProcess(cfg Config) (*process, error) {
	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Env = cfg.Env
	cmd.Stderr = cfg.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("cryptoworker: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("cryptoworker: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("cryptoworker: start child: %w", err)
	}
	return &process{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

// call sends one request and waits for its answer. The read runs in a goroutine
// so the wait can be bounded; on timeout or cancellation the caller kills the
// child, which unblocks that goroutine through the closed pipe.
func (p *process) call(ctx context.Context, req request, timeout time.Duration) (response, error) {
	if err := writeFrame(p.stdin, req); err != nil {
		return response{}, fmt.Errorf("cryptoworker: send: %w", err)
	}
	type result struct {
		resp response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var resp response
		err := readFrame(p.stdout, &resp)
		ch <- result{resp, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil {
			return response{}, fmt.Errorf("cryptoworker: receive: %w", res.err)
		}
		return res.resp, nil
	case <-timer.C:
		return response{}, errCallTimeout
	case <-ctx.Done():
		return response{}, ctx.Err()
	}
}

// kill terminates the child and releases its pipes. Killing is the point: the
// operating system reclaims the leaked and corrupted library state along with the
// address space.
func (p *process) kill() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	p.stdin.Close()
	p.stdout.Close()
	// Reap the child so it does not linger as a zombie. The pipes are closed, so
	// Wait cannot block on output copying.
	_ = p.cmd.Wait()
}

// processRSSBytes reads a process's resident size from /proc. It reports false
// where /proc is absent (any non-Linux host), leaving the op budget as the only
// recycle trigger there.
func processRSSBytes(pid int) (int64, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * int64(os.Getpagesize()), true
}
