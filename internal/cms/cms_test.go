package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// ctxTag wraps DER content in a context-specific tag (explicit or implicit-set).
func ctxTag(tag int, compound bool, content []byte) []byte {
	rv := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: compound, Bytes: content}
	b, _ := asn1.Marshal(rv)
	return b
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wrapContentInfo wraps a SignedData DER as ContentInfo(signedData).
func wrapContentInfo(t *testing.T, signedData []byte) []byte {
	t.Helper()
	oid := mustMarshal(t, oidSignedData)
	content := ctxTag(0, true, signedData) // [0] EXPLICIT SignedData
	seq := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(oid, content...)}
	return mustMarshal(t, seq)
}

func sha256Alg(t *testing.T) []byte {
	return mustMarshal(t, algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}})
}

func TestParseTimestampToken(t *testing.T) {
	genTime := time.Date(2026, 5, 8, 6, 45, 13, 0, time.UTC)
	tst := tstInfoRaw{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 398, 3, 3, 2, 6, 4},
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
			HashedMessage: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		SerialNumber: big.NewInt(0x1234),
		GenTime:      genTime,
	}
	tstDER := mustMarshal(t, tst)

	// encapContentInfo { eContentType=TSTInfo, [0] EXPLICIT OCTET STRING(tstDER) }
	eciType := mustMarshal(t, oidTSTInfo)
	octet := mustMarshal(t, tstDER) // OCTET STRING
	eContent := ctxTag(0, true, octet)
	eci := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(eciType, eContent...)}
	eciDER := mustMarshal(t, eci)

	// signedData { version, digestAlgs SET(empty), encapContentInfo, signerInfos SET(empty) }
	emptySet := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true})
	ver := mustMarshal(t, 3)
	sdBody := bytes.Join([][]byte{ver, emptySet, eciDER, emptySet}, nil)
	sd := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBody}
	token := wrapContentInfo(t, mustMarshal(t, sd))

	ts, err := ParseTimestampToken(token)
	if err != nil {
		t.Fatalf("ParseTimestampToken: %v", err)
	}
	if ts.Policy != "1.2.398.3.3.2.6.4" {
		t.Errorf("policy = %q", ts.Policy)
	}
	if ts.SerialNumberHex != "1234" {
		t.Errorf("serial = %q, want 1234", ts.SerialNumberHex)
	}
	if ts.GenTime == nil || !ts.GenTime.Equal(genTime) {
		t.Errorf("genTime = %v, want %v", ts.GenTime, genTime)
	}
	if ts.HashAlgorithmOID != "2.16.840.1.101.3.4.2.1" {
		t.Errorf("hashAlg = %q", ts.HashAlgorithmOID)
	}
	if !bytes.Equal(ts.Hash, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("hash = %x", ts.Hash)
	}
}

func TestParseSigners_SigningTime(t *testing.T) {
	signTime := time.Date(2026, 5, 8, 7, 0, 0, 0, time.UTC)

	// signingTime attribute: SEQUENCE { oid, SET { UTCTime } }
	attrOID := mustMarshal(t, oidSigningTime)
	timeVal := mustMarshal(t, signTime) // UTCTime for 2026
	attrValues := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: timeVal})
	attr := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(attrOID, attrValues...)}
	signedAttrs := ctxTag(0, true, mustMarshal(t, attr)) // [0] IMPLICIT SET OF Attribute

	// sid = issuerAndSerialNumber { issuer Name(empty SEQ), serial }
	emptyName := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
	serial := mustMarshal(t, big.NewInt(0xABCD))
	sid := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(emptyName, serial...)})

	gostOID := asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}
	si := bytes.Join([][]byte{
		mustMarshal(t, 1), // version
		sid,
		sha256Alg(t), // digestAlgorithm
		signedAttrs,
		mustMarshal(t, algorithmIdentifier{Algorithm: gostOID}), // signatureAlgorithm
		mustMarshal(t, []byte{0x01, 0x02}),                      // signature OCTET STRING
	}, nil)
	siSeq := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: si})
	signerInfos := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: siSeq})

	emptySet := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true})
	// encapContentInfo { eContentType=data }
	dataOID := mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	eci := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: dataOID})

	sdBody := bytes.Join([][]byte{mustMarshal(t, 1), emptySet, eci, signerInfos}, nil)
	sd := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBody})
	cmsDER := wrapContentInfo(t, sd)

	signers, err := ParseSigners(cmsDER)
	if err != nil {
		t.Fatalf("ParseSigners: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(signers))
	}
	s := signers[0]
	if s.SerialNumberHex != "ABCD" {
		t.Errorf("serial = %q, want ABCD", s.SerialNumberHex)
	}
	if s.SignatureAlgorithmOID != "1.2.398.3.10.1.1.2.3.2" {
		t.Errorf("sigAlg = %q", s.SignatureAlgorithmOID)
	}
	if s.SigningTime == nil || !s.SigningTime.Equal(signTime) {
		t.Errorf("signingTime = %v, want %v", s.SigningTime, signTime)
	}
}

func TestParseSigners_NotCMS(t *testing.T) {
	if _, err := ParseSigners([]byte("junk")); err == nil {
		t.Error("expected error for non-CMS input")
	}
}
