//go:build qoltanba_functional

// End-to-end tests of the domain service and the REST transport against the
// REAL Kalkan library. They are not part of normal CI: they need the native
// library (BYOL) and a consumer test key, and run behind the qoltanba_functional
// build tag in the same linux/amd64 environment as the driver functional tests
// (see test/functional/run.sh). The tests exercise the full stack —
// transport → core.Service → provider (real Kalkan) — with no fakes.
//
// Environment (shared with the driver functional tests):
//
//	QOLTANBA_LIB   path to libkalkancryptwr-64.so
//	QOLTANBA_KEY   path to a test .p12
//	QOLTANBA_PASS  container password (default Qwerty12)
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/keysource"
	"github.com/uelnur/qoltanba/internal/native"
	grpctransport "github.com/uelnur/qoltanba/internal/transport/grpc"
	"github.com/uelnur/qoltanba/internal/transport/rest"
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

func testKey(t *testing.T) core.KeySpec {
	t.Helper()
	path := os.Getenv("QOLTANBA_KEY")
	if path == "" {
		t.Skip("QOLTANBA_KEY not set")
	}
	pass := os.Getenv("QOLTANBA_PASS")
	if pass == "" {
		pass = "Qwerty12"
	}
	return core.KeySpec{Path: &core.PathKey{Path: path, Password: pass}}
}

func TestFunctionalE2E_SignVerifyCMS(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)
	data := []byte("hello e2e")

	signed, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: data, Key: key, OutputPEM: true,
	})
	if err != nil {
		t.Fatalf("sign: %v (lib %+v)", err, signed.LibError)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("empty signature")
	}

	out, err := svc.Verify(context.Background(), core.VerifyInput{
		Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true, ExtractContent: true,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !out.Valid {
		t.Fatalf("signature not valid; libError=%+v", out.LibError)
	}
	if len(out.Signers) == 0 {
		t.Fatal("no signers extracted")
	}
	if !bytes.Equal(out.Content, data) {
		t.Errorf("recovered content = %q, want %q", out.Content, data)
	}
	// The signer certificate should have been parsed and derived.
	s0 := out.Signers[0]
	subj := s0.Certificate.Subject
	if subj.CommonName == "" {
		t.Error("expected a signer commonName")
	}
	// Per-signer facts parsed from the CMS SignedData.
	if s0.SignatureAlgorithm == "" {
		t.Error("expected a per-signer signatureAlgorithm from the CMS")
	}
	t.Logf("signer: CN=%q IIN=%q ownerType=%q roles=%v sigAlg=%q signingTime=%v",
		subj.CommonName, subj.IIN, s0.Certificate.OwnerType, s0.Certificate.Roles,
		s0.SignatureAlgorithm, s0.SigningTime)
}

func TestFunctionalE2E_TSP(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	// The default TSA baked into Kalkan is the production responder, which will not
	// timestamp a test certificate; the test responder must be named explicitly.
	signed, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("tsp"), Key: key, WithTimestamp: boolPtr(true),
		OutputPEM: true, TSAURL: os.Getenv("QOLTANBA_TSA_URL"),
	})
	if err != nil {
		t.Fatalf("sign+tsp: %v (network to TSA required; lib %+v)", err, signed.LibError)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(out.Signers) == 0 {
		t.Fatalf("no signers (valid=%v libErr=%+v)", out.Valid, out.LibError)
	}
	ts := out.Signers[0].Timestamp
	if ts == nil {
		t.Fatal("expected a parsed TSP timestamp")
	}
	if ts.GenTime == nil {
		t.Error("expected TSP genTime")
	}
	if out.Signers[0].CAdESLevel != "T" {
		t.Errorf("cadesLevel = %q, want T", out.Signers[0].CAdESLevel)
	}
	t.Logf("TSP: genTime=%v serial=%q policy=%q hashAlg=%q tsa=%q",
		ts.GenTime, ts.SerialNumber, ts.Policy, ts.HashAlgorithm, ts.TSA)
}

func TestFunctionalE2E_OCSPStructured(t *testing.T) {
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set")
	}
	pool, err := native.Open(native.Config{WrapperPath: lib, PoolSize: 1})
	if err != nil {
		t.Fatalf("open driver: %v", err)
	}
	defer pool.Close()
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
	)

	// Export the owner certificate, then validate it via OCSP.
	info, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
	if err != nil {
		t.Fatalf("cert info: %v", err)
	}
	out, err := svc.Validate(context.Background(), core.ValidateInput{
		Cert: info.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
		ResponderURL: os.Getenv("QOLTANBA_OCSP_URL"), WantOCSP: true,
	})
	if err != nil {
		t.Fatalf("ocsp validate: %v", err)
	}
	t.Logf("OCSP: revoked=%v reason=%q thisUpdate=%v nextUpdate=%v producedAt=%v respBytes=%d",
		out.Status.Revoked, out.Status.Reason, out.Status.ThisUpdate, out.Status.NextUpdate,
		out.Status.ProducedAt, len(out.OCSPResponse))
	if out.Status.CheckedAt == nil {
		t.Error("expected CheckedAt set")
	}
}

func TestFunctionalE2E_CertInfoFromKey(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: key})
	if err != nil {
		t.Fatalf("cert info: %v", err)
	}
	c := out.Certificate
	if c.SerialNumber == "" {
		t.Error("expected a certificate serial number")
	}
	if c.NotBefore == nil || c.NotAfter == nil {
		t.Error("expected validity dates")
	}
	if c.OwnerType == "" {
		t.Error("expected a derived owner type")
	}
	t.Logf("cert: serial=%s ownerType=%s keyAlg=%s roles=%v warnings=%d",
		c.SerialNumber, c.OwnerType, c.KeyAlgorithm, c.Roles, len(out.Warnings))
}

func TestFunctionalE2E_RESTVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatCMS, Data: []byte("rest"), Key: key, OutputPEM: true})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", rest.New(svc).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"format": "cms", "signature": signed.Signature, "inputPem": true, "extractContent": true,
	})
	resp, err := http.Post(srv.URL+"/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /verify: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out core.VerifyOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Valid {
		t.Fatalf("not valid via REST; libError=%+v", out.LibError)
	}
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

func TestFunctionalE2E_ChainVerified(t *testing.T) {
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set")
	}
	pool, err := native.Open(native.Config{WrapperPath: lib, PoolSize: 1})
	if err != nil {
		t.Fatalf("open driver: %v", err)
	}
	defer pool.Close()

	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
		core.WithChainVerification(true),
	)
	key := testKey(t)

	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatCMS, Data: []byte("chain"), Key: key, OutputPEM: true})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(out.Signers) == 0 {
		t.Fatal("no signers")
	}
	s := out.Signers[0]
	t.Logf("chainComplete=%v trustAnchorFound=%v chainSignaturesVerified=%v chainLen=%d",
		s.ChainComplete, s.TrustAnchorFound, s.ChainSignaturesVerified, len(s.Chain))
	if !s.ChainComplete {
		t.Error("expected a complete chain to the test root")
	}
	if !s.ChainSignaturesVerified {
		t.Error("expected Kalkan to cryptographically validate the GOST chain")
	}
}

func TestFunctionalE2E_GRPCVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatCMS, Data: []byte("grpc"), Key: key, OutputPEM: true})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	gs := grpclib.NewServer()
	grpctransport.New(svc).Register(gs)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	conn, err := grpclib.NewClient("passthrough:///bufnet",
		grpclib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpclib.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewSignatureServiceClient(conn)
	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Format: pb.SignatureFormat_CMS, Signature: signed.Signature, InputPem: true, ExtractContent: true,
	})
	if err != nil {
		t.Fatalf("gRPC Verify: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("not valid via gRPC; libError=%+v", resp.GetLibError())
	}
	if len(resp.GetSigners()) == 0 {
		t.Fatal("no signers via gRPC")
	}
	t.Logf("gRPC signer CN=%q ownerType=%q chainComplete=%v",
		resp.GetSigners()[0].GetCertificate().GetSubject().GetCommonName(),
		resp.GetSigners()[0].GetCertificate().GetOwnerType(),
		resp.GetSigners()[0].GetChainComplete())
}
