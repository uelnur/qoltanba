//go:build qoltanba_functional

package e2e

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/keysource"
)

// TestSoakResourceGrowth runs the operation mix in a long loop and reports how
// memory, file descriptors, child processes and temp files move. It answers a
// deployment question the functional tests do not: whether a long-lived service
// grows without bound — the library allocates outside Go's heap, so only the
// process view shows it.
//
// Off by default: set QOLTANBA_SOAK to the iteration count (e.g. 2000). Linux
// only, since it reads /proc.
func TestSoakResourceGrowth(t *testing.T) {
	iterations := soakIterations(t, "QOLTANBA_SOAK")
	if iterations == 0 {
		t.Skip("QOLTANBA_SOAK not set (iteration count)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("soak measurement reads /proc")
	}
	// The mix is narrowed by environment so a growth signal can be attributed:
	// QOLTANBA_SOAK_NO_VALIDATE drops the revocation legs, QOLTANBA_SOAK_NO_TRUST
	// drops the trust anchors (and with them the per-call CA load).
	noTrust := os.Getenv("QOLTANBA_SOAK_NO_TRUST") != ""
	svc, closer := newSoakService(t, noTrust)
	defer closer()
	key := testKey(t)
	ocspURL := os.Getenv("QOLTANBA_OCSP_URL")
	if os.Getenv("QOLTANBA_SOAK_NO_VALIDATE") != "" {
		ocspURL = ""
	}
	t.Logf("soak mix: iterations=%d trustStore=%v validate=%v", iterations, !noTrust, ocspURL != "")

	// Warm up first: the first calls fault in the library, its trust store and the
	// child process, which is one-off growth, not a leak.
	warmup := iterations / 10
	if warmup < 20 {
		warmup = 20
	}
	var base, last snapshot
	for i := 0; i < iterations; i++ {
		runMix(t, svc, key, ocspURL, noTrust, i)
		switch {
		case i == warmup:
			base = takeSnapshot(t)
			t.Logf("baseline after %d iterations: %s", warmup, base)
		case i > warmup && (i-warmup)%(iterations/5+1) == 0:
			last = takeSnapshot(t)
			t.Logf("iteration %d: %s", i, last)
		}
	}
	last = takeSnapshot(t)
	t.Logf("final after %d iterations: %s", iterations, last)

	growthKB := last.rssKB - base.rssKB
	perIterBytes := float64(growthKB) * 1024 / float64(iterations-warmup)
	t.Logf("RSS growth after warmup: %+d KB total, %.1f bytes/iteration (children: %+d KB)",
		growthKB, perIterBytes, last.childRSSKB-base.childRSSKB)

	// Descriptors, children and temp files must be flat: each is bounded by the
	// design (fixed pipes per child, cleanup on every temp file), so any drift is
	// a real leak rather than allocator noise.
	if last.fds > base.fds+8 {
		t.Errorf("file descriptors grew %d → %d", base.fds, last.fds)
	}
	if last.children > base.children {
		t.Errorf("child processes grew %d → %d", base.children, last.children)
	}
	if last.zombies > 0 {
		t.Errorf("%d zombie children — a killed child was not reaped", last.zombies)
	}
	if last.tempFiles > base.tempFiles+2 {
		t.Errorf("kalkan temp files grew %d → %d — a cleanup path is missing", base.tempFiles, last.tempFiles)
	}
}

// runMix performs one round of the operation mix that reproduces the library's
// corruption: signing and verification in both container formats plus revocation
// checks of a valid and a revoked certificate.
func runMix(t *testing.T, svc *core.Service, key core.KeySpec, ocspURL string, noTrust bool, i int) {
	t.Helper()
	ctx := context.Background()
	payload := []byte(fmt.Sprintf("soak %d", i))
	only := os.Getenv("QOLTANBA_SOAK_ONLY")
	does := func(op string) bool { return only == "" || only == op }

	// Without anchors the library cannot build the signer chain, so the time check
	// must be relaxed for the run to proceed.
	var signed core.SignOutput
	var err error
	if does("sign-cms") || does("verify-cms") {
		signed, err = svc.Sign(ctx, core.SignInput{
			Format: core.FormatCMS, Data: payload, Key: key, OutputPEM: true, NoCheckCertTime: noTrust,
		})
		if err != nil {
			t.Fatalf("iteration %d: sign cms: %v", i, err)
		}
	}
	if does("verify-cms") {
		if _, err := svc.Verify(ctx, core.VerifyInput{
			Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true, ExtractContent: true,
		}); err != nil {
			t.Fatalf("iteration %d: verify cms: %v", i, err)
		}
	}

	if does("sign-xml") || does("verify-xml") {
		xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root><data>soak</data></root>`)
		signedXML, err := svc.Sign(ctx, core.SignInput{
			Format: core.FormatXML, Data: xml, Key: key, NoCheckCertTime: noTrust,
		})
		if err != nil {
			t.Fatalf("iteration %d: sign xml: %v", i, err)
		}
		if does("verify-xml") {
			if _, err := svc.Verify(ctx, core.VerifyInput{Format: core.FormatXML, Signature: signedXML.Signature}); err != nil {
				t.Fatalf("iteration %d: verify xml: %v", i, err)
			}
		}
	}

	if !does("certinfo") && ocspURL == "" {
		return
	}
	info, err := svc.CertInfo(ctx, core.CertInfoInput{Key: key})
	if err != nil {
		t.Fatalf("iteration %d: cert info: %v", i, err)
	}
	if ocspURL == "" {
		return
	}
	for _, cert := range certsUnderCheck(t, svc, info) {
		if _, err := svc.Validate(ctx, core.ValidateInput{
			Cert: cert, Format: core.EncodingPEM, Method: core.MethodOCSP,
			ResponderURL: ocspURL, WantOCSP: true,
		}); err != nil {
			t.Fatalf("iteration %d: validate: %v", i, err)
		}
	}
}

// certsUnderCheck returns the signer certificate plus, when a revoked key is
// configured, the revoked one — the revoked verdict is the path that corrupts the
// library, so a soak run without it would miss the interesting allocation path.
func certsUnderCheck(t *testing.T, svc *core.Service, info core.CertInfoOutput) [][]byte {
	t.Helper()
	certs := [][]byte{info.Certificate.PEM}
	if os.Getenv("QOLTANBA_KEY_REVOKED") == "" {
		return certs
	}
	revoked, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: keyFromEnv(t, "QOLTANBA_KEY_REVOKED")})
	if err != nil {
		t.Fatalf("cert info (revoked): %v", err)
	}
	return append(certs, revoked.Certificate.PEM)
}

// newSoakService builds the service with or without a trust store, so a run can
// tell native growth caused by the per-call CA load from growth caused by the
// crypto operations themselves.
func newSoakService(t *testing.T, noTrust bool) (*core.Service, func()) {
	t.Helper()
	if !noTrust {
		return newService(t)
	}
	return core.New(requireProvider(t), core.WithKeySource(keysource.New(keysource.WithInline(true)))), func() {}
}

type snapshot struct {
	rssKB      int
	heapKB     int
	heapSysKB  int
	childRSSKB int
	fds        int
	children   int
	zombies    int
	tempFiles  int
}

func (s snapshot) String() string {
	return fmt.Sprintf("rss=%dKB goHeap=%dKB(sys %dKB) children=%d(rss=%dKB) fds=%d zombies=%d tempFiles=%d",
		s.rssKB, s.heapKB, s.heapSysKB, s.children, s.childRSSKB, s.fds, s.zombies, s.tempFiles)
}

func takeSnapshot(t *testing.T) snapshot {
	t.Helper()
	// Go's own heap is measured alongside RSS: a flat heap with a growing RSS
	// means the growth is in the native library, not in our code.
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := snapshot{
		rssKB:     rssKB(t, "self"),
		heapKB:    int(ms.HeapAlloc / 1024),
		heapSysKB: int(ms.HeapSys / 1024),
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		s.fds = len(entries)
	}
	self := os.Getpid()
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + p.Name() + "/stat")
		if err != nil {
			continue
		}
		// "pid (comm) state ppid …" — comm may contain spaces, so parse after ')'.
		rest := stat[strings.LastIndexByte(string(stat), ')')+2:]
		fields := strings.Fields(string(rest))
		if len(fields) < 2 || fields[1] != strconv.Itoa(self) {
			continue
		}
		s.children++
		if fields[0] == "Z" {
			s.zombies++
			continue
		}
		s.childRSSKB += rssKB(t, strconv.Itoa(pid))
	}
	tmp, _ := os.ReadDir(os.TempDir())
	for _, e := range tmp {
		if strings.HasPrefix(e.Name(), "kalkan-") {
			s.tempFiles++
		}
	}
	return s
}

func rssKB(t *testing.T, pid string) int {
	t.Helper()
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.Atoi(fields[1])
				return kb
			}
		}
	}
	return 0
}

func soakIterations(t *testing.T, name string) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s = %q, want an integer", name, raw)
	}
	return n
}
