//go:build qoltanba_functional

// Package e2e holds end-to-end tests of the domain service and the transports
// against the REAL Kalkan library. They are not part of normal CI: they need the
// native library (BYOL) and consumer test keys, and run behind the
// qoltanba_functional build tag in the same linux/amd64 environment as the driver
// functional tests (see test/functional/run.sh). The tests exercise the full
// stack — transport → core.Service → provider (real Kalkan) — with no fakes.
//
// Tests are split by feature: sign_verify, certificates, chain, timestamp,
// revocation, batch, jobs, inputref. This file holds the shared harness.
//
// Environment (shared with the driver functional tests):
//
//	QOLTANBA_LIB           path to libkalkancryptwr-64.so
//	QOLTANBA_KEY[2]        test signer .p12 paths
//	QOLTANBA_KEY_REVOKED   a revoked test .p12
//	QOLTANBA_PASS          container password (default Qwerty12)
//	QOLTANBA_CA_ROOT/NCA   trust-anchor cert files
//	QOLTANBA_OCSP_URL / QOLTANBA_TSA_URL   test responders
package e2e

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/keysource"
	"github.com/uelnur/qoltanba/internal/native"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
	grpctransport "github.com/uelnur/qoltanba/internal/transport/grpc"
)

// newService opens the real driver and builds the domain service. It skips the
// test when the library path is not configured.
func newService(t *testing.T) (*core.Service, func()) {
	t.Helper()
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set")
	}
	pool, err := native.Open(native.Config{WrapperPath: lib, PoolSize: 1})
	if err != nil {
		t.Fatalf("open driver: %v", err)
	}
	// Signing under the default strict time check anchors the signer's chain, so
	// the test CA(s) must be in the store — supplied via the trust store.
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
	)
	return svc, func() { _ = pool.Close() }
}

func testKey(t *testing.T) core.KeySpec { return keyFromEnv(t, "QOLTANBA_KEY") }

// testKey2 is a second signer with a different profile (legal person / first
// head), used for multi-signature and legal-person field coverage.
func testKey2(t *testing.T) core.KeySpec { return keyFromEnv(t, "QOLTANBA_KEY2") }

func keyFromEnv(t *testing.T, env string) core.KeySpec {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Skipf("%s not set", env)
	}
	pass := os.Getenv("QOLTANBA_PASS")
	if pass == "" {
		pass = "Qwerty12"
	}
	return core.KeySpec{Path: &core.PathKey{Path: path, Password: pass}}
}

func boolPtr(b bool) *bool { return &b }

// envTrust is a core.TrustStore built from the test CA files the harness exports.
type envTrust struct{ anchors []core.TrustedCert }

func (e envTrust) Anchors() []core.TrustedCert { return e.anchors }

func loadEnvTrust(t *testing.T) envTrust {
	t.Helper()
	var anchors []core.TrustedCert
	for _, e := range []struct {
		env   string
		inter bool
	}{{"QOLTANBA_CA_ROOT", false}, {"QOLTANBA_CA_NCA", true}} {
		path := os.Getenv(e.env)
		if path == "" {
			t.Skipf("%s not set", e.env)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", e.env, err)
		}
		anchors = append(anchors, core.TrustedCert{Cert: raw, Intermediate: e.inter})
	}
	return envTrust{anchors}
}

// signN produces n real attached-CMS signatures over distinct payloads.
func signN(t *testing.T, svc *core.Service, n int) [][]byte {
	t.Helper()
	key := testKey(t)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		out, err := svc.Sign(context.Background(), core.SignInput{
			Format: core.FormatCMS, Data: []byte{'d', byte('0' + i)}, Key: key, OutputPEM: true,
		})
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		sigs[i] = out.Signature
	}
	return sigs
}

// startJobManager builds and starts an async-job manager whose executor runs
// through the shared dispatch router over the real service.
func startJobManager(t *testing.T, svc *core.Service) (*jobs.Manager, func()) {
	t.Helper()
	exec := func(ctx context.Context, op string, req json.RawMessage) (any, error) {
		return dispatch.Handle(ctx, svc, op, req)
	}
	mgr := jobs.New(jobs.NewMemStore(), exec, dispatch.Valid, jobs.Config{Workers: 2})
	ctx, cancel := context.WithCancel(context.Background())
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("job manager start: %v", err)
	}
	return mgr, func() { cancel(); mgr.Wait() }
}

// grpcClient dials an in-process gRPC server over the real service, optionally
// with async jobs enabled.
func grpcClient(t *testing.T, svc *core.Service, mgr *jobs.Manager) (pb.SignatureServiceClient, func()) {
	t.Helper()
	var opts []grpctransport.Option
	if mgr != nil {
		opts = append(opts, grpctransport.WithJobs(mgr))
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpclib.NewServer()
	grpctransport.New(svc, opts...).Register(gs)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpclib.NewClient("passthrough:///bufnet",
		grpclib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpclib.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		t.Fatalf("dial: %v", err)
	}
	client := pb.NewSignatureServiceClient(conn)
	return client, func() { _ = conn.Close(); gs.Stop() }
}
