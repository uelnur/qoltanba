//go:build qoltanba_functional

package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
)

// The combinations the first integrator hit in production. Each was silent: the
// library reported success, the service passed it on, and the caller only found
// out when verification of the "signature" failed. They are here because the rest
// of the suite signs PEM, attached, with the certificate-time check on — the one
// corner where all of this happens to work.

// TestFunctionalE2E_SignDEROutput covers the DER request. The library fills the
// output buffer only for KC_OUT_PEM, so the driver signs PEM and unwraps.
func TestFunctionalE2E_SignDEROutput(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	der, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("der-output"), Key: key,
		Detached: true, OutputPEM: false,
	})
	if err != nil {
		t.Fatalf("sign DER: %v (lib %+v)", err, der.LibError)
	}
	if len(der.Signature) < 1000 {
		t.Fatalf("DER container is %d bytes — the output was truncated", len(der.Signature))
	}
	if bytes.HasPrefix(der.Signature, []byte("-----BEGIN")) {
		t.Error("outputPem=false must not return a PEM wrapper")
	}
	// It has to verify as the DER it claims to be.
	out, verr := svc.Verify(context.Background(), core.VerifyInput{
		Format: core.FormatCMS, Signature: der.Signature, Data: []byte("der-output"),
		Detached: true, InputPEM: false, RevocationCheck: boolPtr(false),
	})
	if verr != nil {
		t.Fatalf("verify DER: %v", verr)
	}
	if !out.Valid || len(out.Signers) != 1 {
		t.Fatalf("verify DER: valid=%v signers=%d — a DER container must verify like its PEM twin",
			out.Valid, len(out.Signers))
	}
}

// TestFunctionalE2E_VerifyDERInput pins the defect behind "valid with no
// signers": the certificate walk needs the container's encoding named, and
// without it a DER container verified while naming nobody.
func TestFunctionalE2E_VerifyDERInput(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	signed, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("der-input"), Key: key,
		Detached: true, OutputPEM: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block, _ := pem.Decode(signed.Signature)
	if block == nil {
		t.Fatal("signed output is not PEM")
	}

	for _, c := range []struct {
		name     string
		sig      []byte
		inputPEM bool
	}{
		{"PEM", signed.Signature, true},
		{"DER", block.Bytes, false},
	} {
		out, verr := svc.Verify(context.Background(), core.VerifyInput{
			Format: core.FormatCMS, Signature: c.sig, Data: []byte("der-input"),
			Detached: true, InputPEM: c.inputPEM, RevocationCheck: boolPtr(false),
		})
		if verr != nil {
			t.Fatalf("verify %s: %v", c.name, verr)
		}
		if !out.Valid || len(out.Signers) != 1 {
			t.Errorf("verify %s: valid=%v signers=%d, want valid with one signer",
				c.name, out.Valid, len(out.Signers))
		}
	}
}

// TestFunctionalE2E_TimestampWithoutCertTimeCheck pins the refusal. The library
// answers this combination with an empty buffer at rc==0; reporting it as a
// signature handed the caller an empty container carrying cadesLevel T.
func TestFunctionalE2E_TimestampWithoutCertTimeCheck(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	out, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("ts"), Key: key,
		Detached: true, OutputPEM: true, WithTimestamp: boolPtr(true),
		NoCheckCertTime: true, TSAURL: os.Getenv("QOLTANBA_TSA_URL"),
	})
	if err == nil {
		t.Fatalf("expected a refusal, got %d bytes at cadesLevel %q", len(out.Signature), out.CAdESLevel)
	}
	if !errors.Is(err, provider.ErrEmptyOutput) {
		t.Errorf("error = %v, want the empty-output condition", err)
	}
	if len(out.Signature) != 0 {
		t.Error("a refused signing must not hand back a container")
	}
}

// TestFunctionalE2E_TimestampWithCertTimeCheck is the working half of the pair,
// so the refusal above cannot be satisfied by refusing timestamps outright.
func TestFunctionalE2E_TimestampWithCertTimeCheck(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	out, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("ts"), Key: key,
		Detached: true, OutputPEM: true, WithTimestamp: boolPtr(true),
		TSAURL: os.Getenv("QOLTANBA_TSA_URL"),
	})
	if err != nil {
		t.Fatalf("sign with timestamp: %v (lib %+v)", err, out.LibError)
	}
	if len(out.Signature) < 1000 || out.CAdESLevel != "T" {
		t.Fatalf("len=%d cadesLevel=%q, want a full container at T", len(out.Signature), out.CAdESLevel)
	}
}

// TestFunctionalE2E_ExtractBinaryContent covers content recovery over bytes with
// embedded NULs: the recovered buffer used to be cut at the first one, silently
// truncating any binary document.
func TestFunctionalE2E_ExtractBinaryContent(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	// A PDF/ZIP shape: a header, a NUL, then more payload.
	content := append([]byte("%PDF-1.7\x00"), bytes.Repeat([]byte{0x00, 0x01, 0x02, 0xff}, 64)...)
	signed, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: content, Key: key, OutputPEM: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{
		Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true,
		ExtractContent: true, RevocationCheck: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !bytes.Equal(out.Content, content) {
		t.Errorf("recovered %d bytes of %d — binary content must survive intact",
			len(out.Content), len(content))
	}
}

// TestFunctionalE2E_RevocationUsesCertificateAIA covers the responder resolution
// against the live test CA: no responder is named, and the check still reaches
// the one the certificate publishes rather than the library's production default.
func TestFunctionalE2E_RevocationUsesCertificateAIA(t *testing.T) {
	svc, closer := newService(t)
	defer closer()

	info, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
	if err != nil {
		t.Fatalf("cert info: %v", err)
	}
	if len(info.Certificate.OCSPURLs) == 0 {
		t.Fatalf("the test certificate publishes no OCSP responder; nothing to resolve")
	}
	t.Logf("AIA responder from the certificate: %v", info.Certificate.OCSPURLs)

	out, err := svc.Validate(context.Background(), core.ValidateInput{
		Cert: info.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !out.Status.Determinate {
		t.Fatalf("status undetermined without an explicit responder: %+v (lib %+v)",
			out.Status, out.Status.LibError)
	}
	if out.Status.Revoked {
		t.Errorf("the valid test key came back revoked: %+v", out.Status)
	}
}
