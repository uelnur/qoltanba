//go:build qoltanba_functional

package native

import (
	"context"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

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
