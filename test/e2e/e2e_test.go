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
	"slices"
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

// TestFunctionalE2E_CertFieldsGolden pins the parsed certificate fields for the
// two consumer test keys against the live library — the fast counterpart is
// internal/core TestParseCertificate_Golden*, which parses the same values with
// no native library. Together they catch drift in the X509CertificateGetInfo
// rendering (e.g. a dropped "name=" prefix) and in the RK derivation.
func TestFunctionalE2E_CertFieldsGolden(t *testing.T) {
	svc, closer := newService(t)
	defer closer()

	t.Run("individual", func(t *testing.T) {
		out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
		if err != nil {
			t.Fatalf("cert info: %v", err)
		}
		c := out.Certificate
		if c.Subject.CommonName != "ТЕСТОВ ТЕСТ" {
			t.Errorf("CommonName = %q, want ТЕСТОВ ТЕСТ", c.Subject.CommonName)
		}
		if c.Subject.IIN != "123456789011" {
			t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
		}
		if c.Subject.BIN != "" {
			t.Errorf("BIN = %q, want empty for an individual", c.Subject.BIN)
		}
		if c.OwnerType != "INDIVIDUAL" {
			t.Errorf("OwnerType = %q, want INDIVIDUAL", c.OwnerType)
		}
		if len(c.Roles) != 1 || c.Roles[0] != "INDIVIDUAL" {
			t.Errorf("Roles = %v, want [INDIVIDUAL]", c.Roles)
		}
		if c.KeyAlgorithm != "gost2015-512" {
			t.Errorf("KeyAlgorithm = %q, want gost2015-512", c.KeyAlgorithm)
		}
		if c.SerialNumber != "6C425659BD2FC6DC587B871AEDE1857727CF8451" {
			t.Errorf("SerialNumber = %q", c.SerialNumber)
		}
		if c.NotBefore == nil || c.NotBefore.Year() != 2026 || c.NotAfter == nil || c.NotAfter.Year() != 2027 {
			t.Errorf("validity = [%v, %v], want 2026..2027", c.NotBefore, c.NotAfter)
		}
		if len(out.Warnings) != 0 {
			t.Errorf("unexpected warnings: %v", out.Warnings)
		}
	})

	t.Run("legalPerson", func(t *testing.T) {
		out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey2(t)})
		if err != nil {
			t.Fatalf("cert info: %v", err)
		}
		c := out.Certificate
		if c.Subject.IIN != "123456789011" {
			t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
		}
		if c.Subject.BIN != "123456789021" {
			t.Errorf("BIN = %q, want 123456789021", c.Subject.BIN)
		}
		if c.Subject.Organization != `АО "ТЕСТ"` {
			t.Errorf("Organization = %q, want АО \"ТЕСТ\"", c.Subject.Organization)
		}
		if c.OwnerType != "LEGAL_PERSON" {
			t.Errorf("OwnerType = %q, want LEGAL_PERSON", c.OwnerType)
		}
		if !slices.Contains(c.Roles, "ORGANIZATION") || !slices.Contains(c.Roles, "CEO") {
			t.Errorf("Roles = %v, want to contain ORGANIZATION and CEO", c.Roles)
		}
		if c.SerialNumber != "303EEBDF17969F3EDEDE9BD9828FB1355AABBE4E" {
			t.Errorf("SerialNumber = %q", c.SerialNumber)
		}
	})
}

// TestFunctionalE2E_SignVerifyXMLStrict exercises the XML signing path through the
// service under the default strict cert-time check: the signer's chain is anchored
// during signing, so the CA(s) from the trust store must be loaded before SignXML.
func TestFunctionalE2E_SignVerifyXMLStrict(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root><data>xml strict</data></root>`)
	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatXML, Data: xml, Key: key})
	if err != nil {
		t.Fatalf("sign xml (strict, CA from store): %v (lib %+v)", err, signed.LibError)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("empty XML signature")
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatXML, Signature: signed.Signature})
	if err != nil {
		t.Fatalf("verify xml: %v", err)
	}
	if !out.Valid {
		t.Fatalf("xml signature not valid; libError=%+v", out.LibError)
	}
	if len(out.Signers) == 0 {
		t.Fatal("no signers extracted from XML")
	}
}

// TestFunctionalE2E_SignVerifyWSSEStrict is the WSSE counterpart: it also drives
// the loadTrusted-before-signing path (SignWSSE) under the strict time check.
func TestFunctionalE2E_SignVerifyWSSEStrict(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	// The signed node must carry wsu:Id and NodeID must reference it.
	soap := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
		`<soap:Body wsu:Id="body-1"><data>wsse strict</data></soap:Body></soap:Envelope>`)
	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatWSSE, Data: soap, Key: key, NodeID: "body-1"})
	if err != nil {
		t.Fatalf("sign wsse (strict, CA from store): %v (lib %+v)", err, signed.LibError)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("empty WSSE signature")
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatXML, Signature: signed.Signature})
	if err != nil {
		t.Fatalf("verify wsse: %v", err)
	}
	if !out.Valid {
		t.Fatalf("wsse signature not valid; libError=%+v", out.LibError)
	}
}

// TestFunctionalE2E_RevokedViaOCSP validates the revoked test key through the
// service and asserts the OCSP leg reports it revoked (the CRL leg is covered by
// the driver-level TestFunctional_Revocation).
func TestFunctionalE2E_RevokedViaOCSP(t *testing.T) {
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set")
	}
	ocspURL := os.Getenv("QOLTANBA_OCSP_URL")
	if ocspURL == "" {
		t.Skip("QOLTANBA_OCSP_URL not set")
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

	info, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: keyFromEnv(t, "QOLTANBA_KEY_REVOKED")})
	if err != nil {
		t.Fatalf("cert info (revoked): %v", err)
	}
	out, err := svc.Validate(context.Background(), core.ValidateInput{
		Cert: info.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
		ResponderURL: ocspURL, WantOCSP: true,
	})
	if err != nil {
		t.Fatalf("ocsp validate: %v", err)
	}
	if !out.Status.Revoked {
		t.Errorf("expected revoked=true for the revoked key; status=%+v", out.Status)
	}
	t.Logf("revoked key OCSP: revoked=%v reason=%q", out.Status.Revoked, out.Status.Reason)
}

// TestFunctionalE2E_CoSignCMS adds a second signer (KEY2) to KEY's detached CMS
// and checks both are extracted — exercising ExistingSignature co-sign and the
// multi-signer walk through the service, with the CA loaded for both signatures.
func TestFunctionalE2E_CoSignCMS(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)
	key2 := testKey2(t)
	data := []byte("multi-sign")

	a, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: data, Key: key, Detached: true, OutputPEM: true,
	})
	if err != nil {
		t.Fatalf("sign A: %v (lib %+v)", err, a.LibError)
	}
	ab, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: data, Key: key2, Detached: true,
		InputPEM: true, OutputPEM: true, ExistingSignature: a.Signature,
	})
	if err != nil {
		t.Fatalf("co-sign B: %v (lib %+v)", err, ab.LibError)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{
		Format: core.FormatCMS, Signature: ab.Signature, Data: data, Detached: true, InputPEM: true,
	})
	if err != nil {
		t.Fatalf("verify multi-signature: %v", err)
	}
	if !out.Valid {
		t.Fatalf("multi-signature not valid; libError=%+v", out.LibError)
	}
	if len(out.Signers) < 2 {
		t.Fatalf("expected >=2 signers, got %d", len(out.Signers))
	}
	t.Logf("co-sign signers extracted: %d", len(out.Signers))
}
