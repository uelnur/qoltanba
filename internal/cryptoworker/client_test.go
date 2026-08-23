package cryptoworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// Environment contract between a test and the child process it spawns.
const (
	envHelper    = "QOLTANBA_WORKER_HELPER"
	envMode      = "QOLTANBA_WORKER_MODE"
	envCrashOnce = "QOLTANBA_WORKER_CRASH_ONCE"
)

// TestCryptoWorkerHelper is not a test of its own: it is the child process the
// supervisor tests spawn (re-executing the test binary is the standard way to
// exercise real process boundaries — crash, kill, respawn — without shipping a
// second binary). It exits before the testing package can print to stdout, which
// carries the wire protocol.
func TestCryptoWorkerHelper(t *testing.T) {
	if os.Getenv(envHelper) == "" {
		t.Skip("child-process helper; driven by the supervisor tests")
	}
	// A child asked to crash once does so only for the first process started with
	// this marker file, so a respawn after the crash serves normally.
	if marker := os.Getenv(envCrashOnce); marker != "" {
		if _, err := os.Stat(marker); err != nil {
			_ = os.WriteFile(marker, []byte("crashed"), 0o600)
			os.Exit(3)
		}
	}

	mode := os.Getenv(envMode)
	d := stubDriver{
		Provider: &fake.Provider{Caps: provider.Capabilities{Version: "test", SignCMS: true, VerifyCMS: true}},
		sign: func(provider.SignRequest) (provider.SignResult, error) {
			if mode == "hang" {
				// Sleep rather than block forever: a blocked runtime would be detected
				// as a deadlock and kill the child, which is a crash, not a hang.
				time.Sleep(time.Hour)
			}
			if mode == "liberror" {
				return provider.SignResult{}, provider.NewNativeError("SignCMS", 0x08F0000B, "expired", provider.ErrCertExpired)
			}
			return provider.SignResult{Signature: []byte("sig:" + strconv.Itoa(os.Getpid()))}, nil
		},
		validate: func(provider.ValidateRequest) (provider.ValidateResult, error) {
			if mode == "revoked" {
				return provider.ValidateResult{Status: provider.StatusRevoked}, nil
			}
			return provider.ValidateResult{Status: provider.StatusGood}, nil
		},
		selfTest: provider.SelfTestResult{Ran: true, OK: true, Algorithm: "SHA256"},
	}
	_ = Serve(context.Background(), os.Stdin, os.Stdout, d)
	os.Exit(0)
}

// helperConfig builds a Config that spawns this test binary as the child.
func helperConfig(t *testing.T, mode string, env ...string) Config {
	t.Helper()
	return Config{
		Command:     []string{os.Args[0], "-test.run=^TestCryptoWorkerHelper$"},
		Env:         append(append(os.Environ(), envHelper+"=1", envMode+"="+mode), env...),
		Size:        1,
		CallTimeout: 5 * time.Second,
		Stderr:      os.Stderr,
	}
}

func startHelper(t *testing.T, cfg Config) *Supervisor {
	t.Helper()
	sup, err := Start(cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Close() })
	return sup
}

func signOnce(t *testing.T, sup *Supervisor) provider.SignResult {
	t.Helper()
	out, err := sup.SignCMS(context.Background(), provider.SignRequest{Data: []byte("d")})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out
}

func TestSupervisorRunsOperationsInChild(t *testing.T) {
	sup := startHelper(t, helperConfig(t, "good"))

	if caps := sup.Capabilities(); caps.Version != "test" || !caps.SignCMS {
		t.Errorf("capabilities not read from the child: %+v", caps)
	}
	self, err := sup.SelfTest(context.Background())
	if err != nil || !self.OK {
		t.Errorf("self-test = %+v, %v", self, err)
	}
	if out := signOnce(t, sup); len(out.Signature) == 0 {
		t.Error("empty signature from the child")
	}
	if got := sup.WorkerStats().Spawns; got != 1 {
		t.Errorf("spawns = %d, want 1", got)
	}
}

// TestSupervisorRetriesAfterChildCrash is the core guarantee: a child dying
// mid-call — the production failure this package mitigates — becomes a retry on a
// fresh process, not a failed request.
func TestSupervisorRetriesAfterChildCrash(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "crashed")
	sup := startHelper(t, helperConfig(t, "good", envCrashOnce+"="+marker))

	signOnce(t, sup)
	stats := sup.WorkerStats()
	if stats.Crashes != 1 {
		t.Errorf("stats = %+v, want 1 crash", stats)
	}
}

// TestSupervisorRecyclesOnOpBudget covers the bound that keeps the library's
// per-operation memory leak from accumulating.
func TestSupervisorRecyclesOnOpBudget(t *testing.T) {
	cfg := helperConfig(t, "good")
	cfg.MaxOps = 1
	sup := startHelper(t, cfg)

	first := signOnce(t, sup)
	second := signOnce(t, sup)
	// Three: the startup capabilities call counts as an operation too.
	if got := sup.WorkerStats().Recycles; got != 3 {
		t.Errorf("recycles = %d, want 3", got)
	}
	// Each signature carries the child's pid, so a genuinely new process shows up
	// as a different value.
	if bytes.Equal(first.Signature, second.Signature) {
		t.Errorf("both calls ran in the same child (%q) — no recycle happened", first.Signature)
	}
}

// TestSupervisorRecyclesOnMemoryBudget drives the memory trigger directly: with a
// 1-byte budget every measured call retires its child, which is what bounds RSS in
// production.
func TestSupervisorRecyclesOnMemoryBudget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("memory budget reads /proc")
	}
	cfg := helperConfig(t, "good")
	cfg.MaxOps = -1
	cfg.MaxRSSBytes = 1
	sup := startHelper(t, cfg)

	signOnce(t, sup)
	if got := sup.WorkerStats().Recycles; got == 0 {
		t.Error("memory budget did not retire the child")
	}
}

func TestSupervisorRecyclesAfterRevokedVerdict(t *testing.T) {
	sup := startHelper(t, helperConfig(t, "revoked"))

	out, err := sup.ValidateCert(context.Background(), provider.ValidateRequest{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if out.Status != provider.StatusRevoked {
		t.Fatalf("status = %v, want revoked", out.Status)
	}
	if got := sup.WorkerStats().Recycles; got != 1 {
		t.Fatalf("recycles = %d, want 1", got)
	}
	if _, err := sup.ValidateCert(context.Background(), provider.ValidateRequest{}); err != nil {
		t.Fatalf("validate after recycle: %v", err)
	}
}

func TestSupervisorKeepAfterRevokedDisablesRecycle(t *testing.T) {
	cfg := helperConfig(t, "revoked")
	cfg.KeepAfterRevoked = true
	cfg.MaxOps = -1
	cfg.MaxRSSBytes = -1
	sup := startHelper(t, cfg)

	if _, err := sup.ValidateCert(context.Background(), provider.ValidateRequest{}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := sup.WorkerStats().Recycles; got != 0 {
		t.Errorf("recycles = %d, want 0", got)
	}
}

// TestSupervisorKillsHungChild covers what an in-process call cannot do: the
// native calls have no timeout, so only killing the process ends a hang.
func TestSupervisorKillsHungChild(t *testing.T) {
	cfg := helperConfig(t, "hang")
	cfg.CallTimeout = 300 * time.Millisecond
	sup := startHelper(t, cfg)

	start := time.Now()
	_, err := sup.SignCMS(context.Background(), provider.SignRequest{})
	if !errors.Is(err, errCallTimeout) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout took %v — the call was not bounded", elapsed)
	}
	if got := sup.WorkerStats().Timeouts; got != 1 {
		t.Errorf("timeouts = %d, want 1", got)
	}
}

// TestSupervisorPropagatesLibraryError checks that a driver error keeps its type
// across the boundary, so the domain still classifies it as a check outcome.
func TestSupervisorPropagatesLibraryError(t *testing.T) {
	sup := startHelper(t, helperConfig(t, "liberror"))

	_, err := sup.SignCMS(context.Background(), provider.SignRequest{})
	if !errors.Is(err, provider.ErrCertExpired) {
		t.Fatalf("err = %v, want ErrCertExpired", err)
	}
}

func TestSupervisorRefusesAfterClose(t *testing.T) {
	sup := startHelper(t, helperConfig(t, "good"))
	if err := sup.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := sup.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	if _, err := sup.SignCMS(context.Background(), provider.SignRequest{}); !errors.Is(err, provider.ErrClosed) {
		t.Errorf("err = %v, want ErrClosed", err)
	}
}

func TestSupervisorHonorsCanceledContext(t *testing.T) {
	sup := startHelper(t, helperConfig(t, "hang"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sup.SignCMS(ctx, provider.SignRequest{}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestStartRequiresCommand(t *testing.T) {
	if _, err := Start(Config{}); err == nil {
		t.Fatal("Start without a command should fail")
	}
}

// TestSupervisorLeaksNoGoroutines exercises the paths that spawn goroutines and
// processes — normal calls, recycles, a crash retry — and checks that nothing is
// left running afterwards. The read goroutine in particular must not outlive a
// call whose child was killed.
func TestSupervisorLeaksNoGoroutines(t *testing.T) {
	settle := func() int {
		var n int
		for i := 0; i < 50; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
			n = runtime.NumGoroutine()
		}
		return n
	}
	before := settle()

	marker := filepath.Join(t.TempDir(), "crashed")
	cfg := helperConfig(t, "good", envCrashOnce+"="+marker)
	cfg.MaxOps = 2
	cfg.Standby = 1
	sup, err := Start(cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := 0; i < 10; i++ {
		signOnce(t, sup)
	}
	if err := sup.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if after := settle(); after > before+2 {
		t.Errorf("goroutines: %d before, %d after — leak", before, after)
	}
}

// TestKillReapsChild guards against zombie children: every killed process must be
// waited on, or a long-lived service accumulates defunct entries.
func TestKillReapsChild(t *testing.T) {
	p, err := startProcess(helperConfig(t, "good"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	p.kill()
	if p.cmd.ProcessState == nil {
		t.Fatal("child was not reaped — Wait did not run")
	}
}

// TestSupervisorSatisfiesProviderPort keeps the supervisor a drop-in for the
// port: the service depends on the interface, not on this type.
func TestSupervisorSatisfiesProviderPort(t *testing.T) {
	var _ provider.Provider = (*Supervisor)(nil)
	var _ Driver = (*Supervisor)(nil)
}

// TestSupervisorServesRecycleFromStandby covers the point of the warm spare: a
// recycled child is replaced by an already-loaded process, so the next request
// does not pay for a library load.
func TestSupervisorServesRecycleFromStandby(t *testing.T) {
	cfg := helperConfig(t, "good")
	cfg.MaxOps = 1
	cfg.Standby = 1
	sup := startHelper(t, cfg)

	// The warmer fills the spare in the background; wait for it rather than racing.
	waitFor(t, func() bool { return len(sup.standby) == 1 }, "standby child never became ready")

	first := signOnce(t, sup)
	second := signOnce(t, sup)
	if bytes.Equal(first.Signature, second.Signature) {
		t.Errorf("both calls ran in the same child (%q) — no recycle happened", first.Signature)
	}
	if got := sup.WorkerStats().HotSwaps; got == 0 {
		t.Fatal("replacement did not come from the standby set")
	}
	// The spare that was consumed must be replaced without being asked again.
	waitFor(t, func() bool { return len(sup.standby) == 1 }, "standby set was not refilled")
}

func TestSupervisorWithoutStandbyStartsOnDemand(t *testing.T) {
	cfg := helperConfig(t, "good")
	cfg.MaxOps = 1
	cfg.Standby = 0
	sup := startHelper(t, cfg)

	signOnce(t, sup)
	signOnce(t, sup)
	if got := sup.WorkerStats().HotSwaps; got != 0 {
		t.Errorf("hot swaps = %d, want 0 with standby disabled", got)
	}
}

// TestCloseStopsTheWarmer guards the shutdown order: a warmer still running after
// the last child is killed would leave an orphan process behind.
func TestCloseStopsTheWarmer(t *testing.T) {
	cfg := helperConfig(t, "good")
	cfg.Standby = 2
	sup, err := Start(cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, func() bool { return len(sup.standby) == 2 }, "standby set never filled")
	if err := sup.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(sup.standby) != 0 {
		t.Errorf("%d standby children survived Close", len(sup.standby))
	}
	// A refill request after Close must not start anything.
	sup.requestWarm()
	time.Sleep(100 * time.Millisecond)
	if len(sup.standby) != 0 {
		t.Error("the warmer kept spawning after Close")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
