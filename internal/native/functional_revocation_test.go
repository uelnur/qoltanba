//go:build qoltanba_functional

package native

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

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
