package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
)

// buildContainer assembles a minimal CMS SignedData with one signer, so the LTV
// tests exercise real DER rather than a mock.
func buildContainer(t *testing.T) []byte {
	t.Helper()
	emptyName := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
	serial := mustMarshal(t, big.NewInt(0xABCD))
	sid := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(emptyName, serial...)})

	gostOID := asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}
	si := bytes.Join([][]byte{
		mustMarshal(t, 1),
		sid,
		sha256Alg(t),
		mustMarshal(t, algorithmIdentifier{Algorithm: gostOID}),
		mustMarshal(t, []byte{0x01, 0x02}),
	}, nil)
	siSeq := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: si})
	signerInfos := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: siSeq})

	emptySet := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true})
	dataOID := mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	eci := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: dataOID})

	sdBody := bytes.Join([][]byte{mustMarshal(t, 1), emptySet, eci, signerInfos}, nil)
	sd := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBody})
	return wrapContentInfo(t, sd)
}

// derBlob makes a syntactically valid DER element to stand in for an OCSP
// response, a CRL or a certificate — the embedding is agnostic to their content.
func derBlob(t *testing.T, tag int, body string) []byte {
	t.Helper()
	return mustMarshal(t, asn1.RawValue{Tag: tag, IsCompound: true,
		Bytes: mustMarshal(t, []byte(body))})
}

func TestAddLTVEmbedsEvidence(t *testing.T) {
	container := buildContainer(t)
	ocsp := derBlob(t, asn1.TagSequence, "ocsp-response")
	crl := derBlob(t, asn1.TagSequence, "crl")
	cert := derBlob(t, asn1.TagSequence, "issuer-cert")

	out, err := AddLTV(container, Evidence{
		OCSPResponses: [][]byte{ocsp}, CRLs: [][]byte{crl}, Certificates: [][]byte{cert},
	})
	if err != nil {
		t.Fatalf("AddLTV: %v", err)
	}
	if bytes.Equal(out, container) {
		t.Fatal("container unchanged")
	}

	got, err := EmbeddedEvidence(out)
	if err != nil {
		t.Fatalf("EmbeddedEvidence: %v", err)
	}
	if len(got.OCSPResponses) != 1 || !bytes.Equal(got.OCSPResponses[0], ocsp) {
		t.Errorf("OCSP evidence = %d entries, want the embedded one", len(got.OCSPResponses))
	}
	if len(got.CRLs) != 1 || !bytes.Equal(got.CRLs[0], crl) {
		t.Errorf("CRL evidence = %d entries", len(got.CRLs))
	}
	if len(got.Certificates) != 1 || !bytes.Equal(got.Certificates[0], cert) {
		t.Errorf("certificate evidence = %d entries", len(got.Certificates))
	}
}

// TestAddLTVKeepsTheSignatureIntact is the property that makes this legitimate:
// evidence goes into unsigned attributes, so everything the signature covers must
// come out byte-for-byte the same.
func TestAddLTVKeepsTheSignatureIntact(t *testing.T) {
	container := buildContainer(t)
	before, err := ParseSigners(container)
	if err != nil {
		t.Fatalf("ParseSigners: %v", err)
	}

	out, err := AddLTV(container, Evidence{OCSPResponses: [][]byte{derBlob(t, asn1.TagSequence, "ocsp")}})
	if err != nil {
		t.Fatalf("AddLTV: %v", err)
	}
	after, err := ParseSigners(out)
	if err != nil {
		t.Fatalf("ParseSigners after: %v", err)
	}

	if len(before) != len(after) {
		t.Fatalf("signers = %d, want %d", len(after), len(before))
	}
	if before[0].SignatureAlgorithmOID != after[0].SignatureAlgorithmOID ||
		before[0].SerialNumberHex != after[0].SerialNumberHex {
		t.Errorf("signer identity changed: %+v vs %+v", before[0], after[0])
	}
	// The signature value itself must survive: locate it in both encodings.
	sig := []byte{0x04, 0x02, 0x01, 0x02} // OCTET STRING 01 02
	if !bytes.Contains(container, sig) || !bytes.Contains(out, sig) {
		t.Error("the signature value did not survive re-encoding")
	}
}

// TestAddLTVIsIdempotent keeps a second pass from duplicating an attribute, which
// a verifier may reject.
func TestAddLTVIsIdempotent(t *testing.T) {
	container := buildContainer(t)
	ocsp := derBlob(t, asn1.TagSequence, "ocsp")

	once, err := AddLTV(container, Evidence{OCSPResponses: [][]byte{ocsp}})
	if err != nil {
		t.Fatalf("first AddLTV: %v", err)
	}
	twice, err := AddLTV(once, Evidence{OCSPResponses: [][]byte{derBlob(t, asn1.TagSequence, "other")}})
	if err != nil {
		t.Fatalf("second AddLTV: %v", err)
	}

	got, err := EmbeddedEvidence(twice)
	if err != nil {
		t.Fatalf("EmbeddedEvidence: %v", err)
	}
	if len(got.OCSPResponses) != 1 || !bytes.Equal(got.OCSPResponses[0], ocsp) {
		t.Errorf("evidence = %d entries; the original must be kept, not duplicated or replaced", len(got.OCSPResponses))
	}
}

func TestAddLTVRejectsBadInput(t *testing.T) {
	container := buildContainer(t)

	if _, err := AddLTV(container, Evidence{}); err == nil {
		t.Error("embedding nothing should be refused")
	}
	if _, err := AddLTV([]byte("junk"), Evidence{CRLs: [][]byte{{0x30, 0x00}}}); err == nil {
		t.Error("a non-CMS input should be refused")
	}
}

func TestEmbeddedEvidenceOnPlainContainer(t *testing.T) {
	got, err := EmbeddedEvidence(buildContainer(t))
	if err != nil {
		t.Fatalf("EmbeddedEvidence: %v", err)
	}
	if !got.Empty() {
		t.Errorf("plain container reported evidence: %+v", got)
	}
}

func TestEmbeddedEvidenceOnGarbage(t *testing.T) {
	if _, err := EmbeddedEvidence([]byte("junk")); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("err = %v, want a parse failure", err)
	}
}
