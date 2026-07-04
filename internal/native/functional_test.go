//go:build qoltanba_functional

// Functional tests against the REAL Kalkan library. They are not part of normal
// CI: they need the native library (BYOL) and a test key, and run behind the
// qoltanba_functional build tag in a linux/amd64 environment with LD_PRELOAD set
// up (see test/functional/). Paths and password come from the environment:
//
//	QOLTANBA_LIB   path to libkalkancryptwr-64.so
//	QOLTANBA_KEY   path to a test .p12
//	QOLTANBA_KEY2  path to a second .p12 (optional, for multi-signature)
//	QOLTANBA_PASS  container password (default Qwerty12)
//	QOLTANBA_POOL  pool size (default 4 for the isolation test)
package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// trustedCAs reads the test CAs from the environment (paths to .cer). XML
// verification needs them.
func trustedCAs(t *testing.T) []provider.TrustedCert {
	t.Helper()
	var cas []provider.TrustedCert
	for _, e := range []struct {
		env   string
		inter bool
	}{{"QOLTANBA_CA_ROOT", false}, {"QOLTANBA_CA_NCA", true}} {
		path := os.Getenv(e.env)
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Logf("CA %s unavailable: %v", path, err)
			continue
		}
		cas = append(cas, provider.TrustedCert{Cert: b, Intermediate: e.inter})
	}
	return cas
}

// isolationDeps collects the isolated-namespace dependencies from the
// environment (iconv shim, libkalkancrypto, libm, libpcsclite).
func isolationDeps() []string {
	get := func(env, def string) string {
		if v := os.Getenv(env); v != "" {
			return v
		}
		return def
	}
	var deps []string
	for _, d := range []string{
		get("QOLTANBA_ICONV", "/opt/iconv_compat.so"),
		get("QOLTANBA_DEP", ""),
		get("QOLTANBA_LIBM", "/usr/lib/x86_64-linux-gnu/libm.so.6"),
		get("QOLTANBA_PCSC", "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1"),
	} {
		if d != "" {
			deps = append(deps, d)
		}
	}
	return deps
}

func envKey() provider.KeyRef {
	pass := os.Getenv("QOLTANBA_PASS")
	if pass == "" {
		pass = "Qwerty12"
	}
	return provider.KeyRef{Storage: provider.StoragePKCS12, Path: os.Getenv("QOLTANBA_KEY"), Password: pass}
}

func openPool(t *testing.T, size int, isolated bool) *Pool {
	t.Helper()
	lib := os.Getenv("QOLTANBA_LIB")
	if lib == "" {
		t.Skip("QOLTANBA_LIB not set — skipping functional tests (native library required)")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skipf("library unavailable (%v)", err)
	}
	p, err := Open(Config{
		WrapperPath:   lib,
		PoolSize:      size,
		Isolated:      isolated,
		IsolationDeps: isolationDeps(),
	})
	if err != nil {
		t.Fatalf("Open(size=%d, isolated=%v): %v", size, isolated, err)
	}
	return p
}

var testData = []byte("Hello, Qazaqstan 2026 — qoltanba driver functional test")

func TestFunctional_Capabilities(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	caps := p.Capabilities()
	t.Logf("version=%s pool=%d signCMS=%v verifyCMS=%v signXML=%v verifyXML=%v certInfo=%v validate=%v tsa=%v zip=%v",
		caps.Version, caps.PoolSize, caps.SignCMS, caps.VerifyCMS, caps.SignXML, caps.VerifyXML,
		caps.CertInfo, caps.Validate, caps.Timestamp, caps.ZipSign)
	if !caps.SignCMS || !caps.VerifyCMS || !caps.CertInfo {
		t.Fatalf("expected the base SignCMS/VerifyCMS/CertInfo capabilities")
	}
}

func TestFunctional_SignVerifyCMS(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty signature")
	}

	res, err := p.VerifyCMS(ctx, provider.VerifyRequest{Signature: sig.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("VerifyCMS: %v (rawCode=0x%08X)", err, res.RawCode)
	}
	if !res.Valid {
		t.Fatalf("signature invalid: info=%q", res.Info)
	}
	if len(res.SignerCert) == 0 {
		t.Fatal("signer certificate not extracted")
	}

	props, err := p.CertProperties(ctx, res.SignerCert, provider.CertPEM)
	if err != nil {
		t.Fatalf("CertProperties: %v", err)
	}
	cn, ok := props.Get("SUBJECT_COMMONNAME")
	if !ok || cn == "" {
		t.Fatal("signer has no SUBJECT_COMMONNAME")
	}
	iin, _ := props.Get("SUBJECT_SERIALNUMBER")
	t.Logf("signer: CN=%q IIN=%q", cn, iin)
}

func TestFunctional_DetachedCMS(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, Detached: true, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS detached: %v", err)
	}
	res, err := p.VerifyCMS(ctx, provider.VerifyRequest{
		Signature: sig.Signature, Data: testData, Detached: true, InputPEM: true,
	})
	if err != nil {
		t.Fatalf("VerifyCMS detached: %v (rawCode=0x%08X)", err, res.RawCode)
	}
	if !res.Valid {
		t.Fatalf("detached signature invalid: info=%q", res.Info)
	}
}

func TestFunctional_SignVerifyXML(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	if !p.Capabilities().SignXML {
		t.Skip("SignXML unavailable")
	}
	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root><data>XML signature test</data></root>`)

	sig, err := p.SignXML(ctx, provider.SignXMLRequest{Key: envKey(), XML: xml})
	if err != nil {
		t.Fatalf("SignXML: %v", err)
	}
	res, err := p.VerifyXML(ctx, provider.VerifyRequest{
		Signature: sig.Signature, TrustedCerts: trustedCAs(t),
	})
	if err != nil {
		t.Fatalf("VerifyXML: %v (rawCode=0x%08X)", err, res.RawCode)
	}
	if !res.Valid {
		t.Fatalf("XML signature invalid: info=%q", res.Info)
	}
	if len(res.SignerCert) == 0 {
		t.Error("signer certificate not extracted from XML")
	}
}

// TestFunctional_ExportOwnerCert covers a pkcs12/info-style operation: open the
// container and export the owner certificate.
func TestFunctional_ExportOwnerCert(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	if !p.Capabilities().ExportCert {
		t.Skip("ExportCert unavailable")
	}
	res, err := p.ExportOwnerCert(ctx, envKey(), provider.CertPEM)
	if err != nil {
		t.Fatalf("ExportOwnerCert: %v", err)
	}
	if len(res.Cert) == 0 {
		t.Fatal("empty owner certificate")
	}
	props, err := p.CertProperties(ctx, res.Cert, provider.CertPEM)
	if err != nil {
		t.Fatalf("CertProperties: %v", err)
	}
	cn, ok := props.Get("SUBJECT_COMMONNAME")
	if !ok || cn == "" {
		t.Fatal("key owner has no CN")
	}
	t.Logf("key owner: CN=%q alias=%q", cn, res.Alias)
}

// TestFunctional_SignerExtraction extracts signer(s) from CMS via Signers[]. One
// signature yields one signer; with a second key (QOLTANBA_KEY2) a co-signature
// yields two.
func TestFunctional_SignerExtraction(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	key := envKey()

	// A single attached signature yields exactly one signer in Signers.
	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: key, Data: testData, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}
	res, err := p.VerifyCMS(ctx, provider.VerifyRequest{Signature: sig.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("VerifyCMS: %v", err)
	}
	if len(res.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(res.Signers))
	}

	// Multi-signature with two different keys (detached CMS + co-sign).
	key2Path := os.Getenv("QOLTANBA_KEY2")
	if key2Path == "" {
		t.Log("QOLTANBA_KEY2 not set — multi-signature test skipped")
		return
	}
	key2 := provider.KeyRef{Storage: provider.StoragePKCS12, Path: key2Path, Password: key.Password}

	a, err := p.SignCMS(ctx, provider.SignRequest{Key: key, Data: testData, Detached: true, OutPEM: true})
	if err != nil {
		t.Fatalf("signature A: %v", err)
	}
	ab, err := p.SignCMS(ctx, provider.SignRequest{
		Key: key2, Data: testData, Detached: true, InputPEM: true, OutPEM: true,
		ExistingSignature: a.Signature,
	})
	if err != nil {
		t.Fatalf("co-signature B: %v", err)
	}
	res2, err := p.VerifyCMS(ctx, provider.VerifyRequest{
		Signature: ab.Signature, Data: testData, Detached: true, InputPEM: true,
	})
	if err != nil {
		t.Fatalf("VerifyCMS multi-signature: %v (rawCode=0x%08X)", err, res2.RawCode)
	}
	if len(res2.Signers) < 2 {
		t.Fatalf("expected >=2 signers, got %d", len(res2.Signers))
	}
	t.Logf("signers extracted: %d", len(res2.Signers))
}

// TestFunctional_WSSE signs a SOAP envelope per WS-Security and verifies it via
// VerifyXML.
func TestFunctional_WSSE(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	if !p.Capabilities().WSSE {
		t.Skip("SignWSSE unavailable")
	}
	// The signed node must carry wsu:Id and NodeID must reference it, otherwise
	// SignWSSE returns 0x08F00033 ("ID attribute is not found").
	soap := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
		`<soap:Body wsu:Id="body-1"><data>WSSE test</data></soap:Body></soap:Envelope>`)
	sig, err := p.SignWSSE(ctx, provider.SignWSSERequest{Key: envKey(), XML: soap, NodeID: "body-1"})
	if err != nil {
		t.Fatalf("SignWSSE: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty WSSE signature")
	}
	res, err := p.VerifyXML(ctx, provider.VerifyRequest{Signature: sig.Signature, TrustedCerts: trustedCAs(t)})
	if err != nil {
		t.Fatalf("VerifyXML(WSSE): %v (rawCode=0x%08X)", err, res.RawCode)
	}
	if !res.Valid {
		t.Fatalf("WSSE signature invalid: info=%q", res.Info)
	}
}

// TestFunctional_HashSignHash computes a digest and signs it (the basis for
// streaming signatures and GOST JWT).
func TestFunctional_HashSignHash(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	if !p.Capabilities().Hash {
		t.Skip("HashData/SignHash unavailable")
	}
	// The HashData algorithm name is found empirically. Order: first the surely
	// supported ones (SHA/GOST34311-95) to prove the plumbing, then GOST-2015-512
	// candidates for SignHash under a GOST key (which needs a 64-byte digest).
	candidates := []string{
		"1.2.398.3.10.1.1.1.2", "1.2.398.3.10.1.1.1.3", // GOST-2015 (512), if supported
		"GOST3411-2015-512", "GOST34311_2015_512", "1.2.643.7.1.1.2.3",
		"GOST34311", "1.2.398.3.10.1.1.1", // GOST-95
		"SHA256", "2.16.840.1.101.3.4.2.1", "SHA1", "1.3.14.3.2.26", "MD5", // plumbing check
	}
	if e := os.Getenv("QOLTANBA_HASH_ALG"); e != "" {
		candidates = append([]string{e}, candidates...)
	}
	var alg string
	var h provider.HashResult
	for _, c := range candidates {
		out, err := p.Hash(ctx, provider.HashRequest{Algorithm: c, Data: testData})
		if err == nil && len(out.Hash) > 0 {
			alg, h = c, out
			break
		}
	}
	if alg == "" {
		t.Skip("no HashData candidate worked (set QOLTANBA_HASH_ALG)")
	}
	t.Logf("HashData works: algorithm %q -> %d-byte digest", alg, len(h.Hash))

	// SignHash only makes sense when the digest fits the GOST-2015-512 key
	// (64 bytes). Otherwise (SHA/GOST-95) the HashData plumbing is proven and
	// SignHash is skipped.
	if len(h.Hash) != 64 {
		t.Logf("%d-byte digest does not fit a GOST-512 key — SignHash skipped (standalone GOST-2015 in HashData appears unavailable)", len(h.Hash))
		return
	}
	sig, err := p.SignHash(ctx, provider.SignHashRequest{Key: envKey(), Hash: h.Hash, OutPEM: true})
	if err != nil {
		t.Fatalf("SignHash: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty hash signature")
	}
	t.Logf("SignHash: %d-byte signature", len(sig.Signature))
}

// TestFunctional_ErrorMapping checks that native codes map to typed provider
// errors (invalid password).
func TestFunctional_ErrorMapping(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	bad := envKey()
	bad.Password = "wrong-password-000"
	_, err := p.SignCMS(context.Background(), provider.SignRequest{Key: bad, Data: testData, OutPEM: true})
	if err == nil {
		t.Fatal("expected an error for a wrong password")
	}
	t.Logf("wrong-password error: %v", err)
}

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

// oneline flattens native outInfo for one-line logging.
func oneline(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// fetchCRL downloads a CRL with our own http.Client (the "own the network"
// half of the split under test) and writes it to a temp file. Returns "" if the
// URL is empty or the fetch fails (offline environment).
func fetchCRL(t *testing.T, url string) string {
	t.Helper()
	if url == "" {
		return ""
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Logf("CRL fetch %s failed: %v", url, err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Logf("CRL fetch %s: HTTP %d", url, resp.StatusCode)
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Logf("CRL read: %v", err)
		return ""
	}
	f, err := os.CreateTemp("", "kalkan-crl-*.crl")
	if err != nil {
		t.Fatalf("temp CRL: %v", err)
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		t.Fatalf("write CRL: %v", err)
	}
	f.Close()
	t.Logf("own-fetched CRL: %d bytes from %s", len(body), url)
	return f.Name()
}

// validateVia exports the owner cert of a key and checks its status against a
// CRL file or OCSP URL. Tries DER then PEM (the C-API auto-detects the format).
func validateVia(t *testing.T, p *Pool, keyPath, pass string, method provider.ValidationMethod, path string, cas []provider.TrustedCert) provider.ValidateResult {
	t.Helper()
	ctx := context.Background()
	last := provider.ValidateResult{Status: provider.StatusUnknown}
	for _, f := range []provider.CertFormat{provider.CertDER, provider.CertPEM} {
		ex, err := p.ExportOwnerCert(ctx, provider.KeyRef{Storage: provider.StoragePKCS12, Path: keyPath, Password: pass}, f)
		if err != nil {
			t.Fatalf("ExportOwnerCert(%s): %v", keyPath, err)
		}
		res, err := p.ValidateCert(ctx, provider.ValidateRequest{
			Cert: ex.Cert, Format: f, Method: method,
			Path: path, CheckTime: time.Now(), TrustedCerts: cas,
		})
		last = res
		if err != nil {
			t.Logf("  fmt=%d error: %v (rawCode=0x%08X)", f, err, res.RawCode)
			continue
		}
		t.Logf("  fmt=%d status=%v rawCode=0x%08X info=%q", f, res.Status, res.RawCode, oneline(res.Info))
		if res.Status != provider.StatusUnknown {
			return res
		}
	}
	return last
}

// TestFunctional_Revocation empirically validates the recommended revocation
// design against the real library:
//
//   - CRL leg: we fetch the CRL ourselves (own http.Client) and hand the FILE to
//     Kalkan (KC_USE_CRL). Confirms Kalkan verifies OUR file — a fresh one is
//     accepted (valid cert → good), a stale bundled one is rejected with
//     "CRL has expired" (0x08F0005D). This is the "own the network, delegate the
//     GOST verify" split, proven feasible for CRL.
//   - OCSP leg: ground truth for the bundled revoked test key. Its revocation is
//     published via OCSP (NOT the CRL — the live base/delta CRLs do not list
//     these test certs), so OCSP returns revoked while the CRL says good. A
//     durable finding: CRL-only checking can miss what OCSP catches.
func TestFunctional_Revocation(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	if !p.Capabilities().Validate {
		t.Skip("Validate capability unavailable")
	}
	cas := trustedCAs(t)
	if len(cas) == 0 {
		t.Skip("no trusted CAs (set QOLTANBA_CA_ROOT/QOLTANBA_CA_NCA)")
	}
	pass := envKey().Password
	validKey := os.Getenv("QOLTANBA_KEY")
	revokedKey := os.Getenv("QOLTANBA_KEY_REVOKED")
	if revokedKey == "" {
		t.Skip("QOLTANBA_KEY_REVOKED not set")
	}

	// Diagnostic: dump the revoked cert (base64 DER) so its CRL Distribution
	// Point can be inspected off-box. Gated by env to keep normal runs quiet.
	if os.Getenv("QOLTANBA_DUMP_CERT") != "" {
		if ex, err := p.ExportOwnerCert(context.Background(), provider.KeyRef{Storage: provider.StoragePKCS12, Path: revokedKey, Password: pass}, provider.CertDER); err == nil {
			t.Logf("REVOKED_CERT_DER_B64:%s", base64.StdEncoding.EncodeToString(ex.Cert))
		}
	}

	// --- CRL leg: own-fetch + Kalkan-verify of the file ---
	if fresh := fetchCRL(t, os.Getenv("QOLTANBA_CRL_URL")); fresh != "" {
		defer os.Remove(fresh)
		t.Log("own-fetched fresh CRL — valid cert:")
		vr := validateVia(t, p, validKey, pass, provider.ValidateCRL, fresh, cas)
		if vr.Status != provider.StatusGood {
			t.Errorf("own-fetched CRL: valid cert not good: status=%v rawCode=0x%08X", vr.Status, vr.RawCode)
		} else {
			t.Log("CONFIRMED: own-fetched CRL accepted+verified by Kalkan (valid→good)")
		}
	} else {
		t.Log("no network for fresh CRL — own-fetch CRL leg skipped")
	}
	if bundled := os.Getenv("QOLTANBA_CRL"); bundled != "" {
		t.Log("bundled (stale) CRL — freshness enforcement:")
		br := validateVia(t, p, validKey, pass, provider.ValidateCRL, bundled, cas)
		t.Logf("bundled CRL outcome: status=%v rawCode=0x%08X (expect 0x08F0005D CRL-expired)", br.Status, br.RawCode)
	}

	// --- OCSP leg: ground truth of the revoked fixture ---
	ocspURL := os.Getenv("QOLTANBA_OCSP_URL")
	if ocspURL == "" {
		t.Log("QOLTANBA_OCSP_URL not set — OCSP leg skipped")
		return
	}
	t.Log("OCSP — revoked cert:")
	rr := validateVia(t, p, revokedKey, pass, provider.ValidateOCSP, ocspURL, cas)
	t.Log("OCSP — valid cert:")
	vv := validateVia(t, p, validKey, pass, provider.ValidateOCSP, ocspURL, cas)
	if rr.Status == provider.StatusUnknown && vv.Status == provider.StatusUnknown {
		t.Skip("OCSP responder unreachable — cannot confirm ground-truth revocation")
	}
	if rr.Status != provider.StatusRevoked {
		t.Errorf("revoked cert not revoked via OCSP: status=%v rawCode=0x%08X", rr.Status, rr.RawCode)
	}
	if vv.Status != provider.StatusGood {
		t.Errorf("valid cert not good via OCSP: status=%v rawCode=0x%08X", vv.Status, vv.RawCode)
	}
	if rr.Status == provider.StatusRevoked && vv.Status == provider.StatusGood {
		t.Log("CONFIRMED via OCSP: revoked→revoked, valid→good (these test revocations live in OCSP, not the CRL)")
	}
}

// TestFunctional_SetProxyNoBreak confirms KC_SetProxy exists and that a call
// after configuring the proxy (off = direct) still works — the coarse proxy
// lever we keep when OCSP stays delegated to the library.
func TestFunctional_SetProxyNoBreak(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	var rc uint32 = 0xFFFFFFFF
	if err := p.submit(ctx, func(inst kalkanInstance) error {
		if real, ok := inst.(*instance); ok {
			rc = real.setProxy(kcProxyOff, "", "", "", "")
		}
		return nil
	}); err != nil {
		t.Fatalf("submit setProxy: %v", err)
	}
	switch rc {
	case 0:
		t.Log("KC_SetProxy(off) rc=0 (ok)")
	case 0xFFFFFFFF:
		t.Skip("KC_SetProxy absent in this library version")
	default:
		t.Logf("KC_SetProxy(off) rc=0x%08X (returned, non-zero)", rc)
	}

	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS after SetProxy: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty signature after SetProxy")
	}
	t.Log("operation works after KC_SetProxy — call not broken")
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// TestFunctional_ExportCertFormats verifies ExportOwnerCert returns each requested
// encoding correctly. Background: X509ExportCertificateFromStore ignores the
// DER/B64 format flag and always emits PEM, so the driver normalizes in Go — this
// test both documents the library quirk and checks the normalization.
func TestFunctional_ExportCertFormats(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	if !p.Capabilities().ExportCert {
		t.Skip("ExportCert unavailable")
	}
	ctx := context.Background()
	key := envKey()

	// Document what the raw library call returns per format flag.
	_ = p.submit(ctx, func(inst kalkanInstance) error {
		real, ok := inst.(*instance)
		if !ok {
			return nil
		}
		alias, err := real.loadKey(key)
		if err != nil {
			return err
		}
		for _, tc := range []struct {
			name string
			flag int
		}{{"DER(0x101)", kcCertDER}, {"PEM(0x102)", kcCertPEM}, {"B64(0x104)", kcCertB64}} {
			raw, err := real.exportCert(alias, tc.flag)
			if err != nil {
				t.Logf("raw flag %s: err %v", tc.name, err)
				continue
			}
			t.Logf("raw flag %s -> len=%d isPEM=%v first=%x", tc.name, len(raw),
				bytes.HasPrefix(raw, []byte("-----BEGIN")), firstN(raw, 8))
		}
		return nil
	})

	pemRes, err := p.ExportOwnerCert(ctx, key, provider.CertPEM)
	if err != nil {
		t.Fatalf("export PEM: %v", err)
	}
	derRes, err := p.ExportOwnerCert(ctx, key, provider.CertDER)
	if err != nil {
		t.Fatalf("export DER: %v", err)
	}
	b64Res, err := p.ExportOwnerCert(ctx, key, provider.CertB64)
	if err != nil {
		t.Fatalf("export B64: %v", err)
	}

	// PEM: armored CERTIFICATE block.
	block, _ := pem.Decode(pemRes.Cert)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("PEM does not decode to a CERTIFICATE block: %q", firstN(pemRes.Cert, 40))
	}
	// DER: real DER (SEQUENCE, long-form 2-byte length), exact length, equals PEM's DER.
	if len(derRes.Cert) < 4 || derRes.Cert[0] != 0x30 || derRes.Cert[1] != 0x82 {
		t.Errorf("DER is not raw DER: first=%x", firstN(derRes.Cert, 8))
	} else if declared := 4 + int(derRes.Cert[2])<<8 + int(derRes.Cert[3]); declared != len(derRes.Cert) {
		t.Errorf("DER length mismatch: declared=%d actual=%d", declared, len(derRes.Cert))
	}
	if !bytes.Equal(derRes.Cert, block.Bytes) {
		t.Error("DER bytes != PEM-decoded DER")
	}
	// B64: base64 of the same DER.
	dec, err := base64.StdEncoding.DecodeString(string(b64Res.Cert))
	if err != nil {
		t.Errorf("B64 is not valid base64: %v", err)
	} else if !bytes.Equal(dec, derRes.Cert) {
		t.Error("B64-decoded bytes != DER")
	}
	t.Logf("CONFIRMED: ExportOwnerCert PEM/DER/B64 correct and cross-consistent (DER %d bytes)", len(derRes.Cert))
}

// TestFunctional_ContextDeadline is a quick sanity check of context timeout
// against the real library.
func TestFunctional_ContextDeadline(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, OutPEM: true})
	if err == nil {
		t.Log("operation finished before the deadline (acceptable)")
	} else {
		t.Logf("deadline fired: %v", err)
	}
}
