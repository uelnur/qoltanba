//go:build qoltanba_functional

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/transport/rest"
)

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
	s0 := out.Signers[0]
	subj := s0.Certificate.Subject
	if subj.CommonName == "" {
		t.Error("expected a signer commonName")
	}
	if s0.SignatureAlgorithm == "" {
		t.Error("expected a per-signer signatureAlgorithm from the CMS")
	}
	t.Logf("signer: CN=%q IIN=%q ownerType=%q roles=%v sigAlg=%q signingTime=%v",
		subj.CommonName, subj.IIN, s0.Certificate.OwnerType, s0.Certificate.Roles,
		s0.SignatureAlgorithm, s0.SigningTime)
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

func TestFunctionalE2E_GRPCVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	signed := signN(t, svc, 1)[0]

	client, done := grpcClient(t, svc, nil)
	defer done()

	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Format: pb.SignatureFormat_CMS, Signature: signed, InputPem: true, ExtractContent: true,
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
