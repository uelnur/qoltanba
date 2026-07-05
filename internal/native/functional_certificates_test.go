//go:build qoltanba_functional

package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

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

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
