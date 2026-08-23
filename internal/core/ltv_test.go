package core

import (
	"bytes"
	"context"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// archiveFixture builds a service whose verify returns one signer and whose
// validate returns a reusable OCSP response.
func archiveFixture(t *testing.T, ocsp []byte) (*Service, []byte) {
	t.Helper()
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{
		verifyResult:   provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}},
		props:          fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		validateResult: provider.ValidateResult{Status: provider.StatusGood, OCSPResponse: ocsp},
	}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}))
	return svc, cmsFixture(t)
}

// cmsFixture is a minimal but real CMS container the LTV code can rewrite.
func cmsFixture(t *testing.T) []byte {
	t.Helper()
	// Built by the cms package's own helper shape: one signer, no attributes.
	der := buildTestCMS(t)
	return der
}

func TestArchiveEmbedsEvidence(t *testing.T) {
	ocsp := []byte{0x30, 0x03, 0x02, 0x01, 0x00} // a small well-formed DER element
	svc, container := archiveFixture(t, ocsp)

	out, err := svc.Archive(context.Background(), ArchiveInput{Signature: container})
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.Level != "LT" {
		t.Errorf("level = %q, want LT", out.Level)
	}
	if out.Embedded.OCSPResponses != 1 {
		t.Errorf("embedded = %+v, want one OCSP response", out.Embedded)
	}

	// The result must actually carry it back.
	got, err := svc.ArchivedEvidence(out.Signature, false)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.OCSPResponses != 1 {
		t.Errorf("read back = %+v", got)
	}
	// The original container carries nothing, which is what makes the difference
	// meaningful.
	before, err := svc.ArchivedEvidence(container, false)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if before.OCSPResponses != 0 || before.Certificates != 0 {
		t.Errorf("original already carried evidence: %+v", before)
	}
}

// TestArchiveWarnsWhenRevocationIsUnavailable covers the partial case: the chain
// is still worth embedding, but the caller must learn that the revocation proof —
// the part that expires with the responder — was not obtained.
func TestArchiveWarnsWhenRevocationIsUnavailable(t *testing.T) {
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{
		verifyResult: provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}},
		props:        fields(map[string]string{"SUBJECT_COMMONNAME": "Leaf"}),
		// The responder answered with nothing reusable.
		validateResult: provider.ValidateResult{Status: provider.StatusGood},
	}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}))

	out, err := svc.Archive(context.Background(), ArchiveInput{Signature: buildTestCMS(t)})
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.Embedded.OCSPResponses != 0 || out.Embedded.Certificates == 0 {
		t.Errorf("embedded = %+v, want the chain but no revocation proof", out.Embedded)
	}
	if len(out.Warnings) == 0 {
		t.Error("a missing revocation proof must be reported, not silently omitted")
	}
}

// TestArchiveRefusesWithoutSigners pins the refusal: a caller who believes a
// document is preserved when it is not is worse off than one who gets an error
// while the evidence is still obtainable.
func TestArchiveRefusesWithoutSigners(t *testing.T) {
	prov := &fakeProvider{verifyResult: provider.VerifyResult{Valid: false}}
	svc := New(prov)

	_, err := svc.Archive(context.Background(), ArchiveInput{Signature: buildTestCMS(t)})
	if err == nil {
		t.Fatal("archiving a container with no signers should fail")
	}
	if !strings.Contains(err.Error(), "signers") {
		t.Errorf("err = %v, want it to explain what is missing", err)
	}
}

func TestArchiveRequiresASignature(t *testing.T) {
	svc := New(&fakeProvider{})
	if _, err := svc.Archive(context.Background(), ArchiveInput{}); err == nil {
		t.Error("archiving without a signature should fail")
	}
}

// TestArchivedEvidenceOnPlainContainer keeps "not archived" distinguishable from
// "archived with nothing".
func TestArchivedEvidenceOnPlainContainer(t *testing.T) {
	svc := New(&fakeProvider{})
	got, err := svc.ArchivedEvidence(buildTestCMS(t), false)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.OCSPResponses != 0 || got.CRLs != 0 || got.Certificates != 0 {
		t.Errorf("plain container reported %+v", got)
	}
}

func TestArchivedEvidenceRejectsGarbage(t *testing.T) {
	svc := New(&fakeProvider{})
	if _, err := svc.ArchivedEvidence([]byte("junk"), false); err == nil {
		t.Error("garbage should be rejected")
	}
	if _, err := svc.ArchivedEvidence([]byte("not pem"), true); err == nil {
		t.Error("invalid PEM should be rejected")
	}
}

// buildTestCMS produces a minimal CMS SignedData with one signer. It is built
// here rather than exported from the cms package: a helper that exists only for
// tests has no business in the production binary.
func buildTestCMS(t *testing.T) []byte {
	t.Helper()
	marshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	seq := func(body []byte) []byte {
		return marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	}
	set := func(body []byte) []byte {
		return marshal(asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: body})
	}

	sid := seq(append(seq(nil), marshal(big.NewInt(0xABCD))...))
	sha256Alg := seq(marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}))
	gostAlg := seq(marshal(asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}))

	signer := seq(bytes.Join([][]byte{
		marshal(1), sid, sha256Alg, gostAlg, marshal([]byte{0x01, 0x02}),
	}, nil))
	eci := seq(marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}))
	signedData := seq(bytes.Join([][]byte{marshal(1), set(nil), eci, set(signer)}, nil))

	content := marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedData,
	})
	return seq(append(marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), content...))
}
