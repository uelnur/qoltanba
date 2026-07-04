// Package cms parses CMS/PKCS#7 SignedData to extract the per-signer facts the
// Kalkan C-API does not surface directly: the signing-time signed attribute, the
// signature algorithm, and the RFC 3161 timestamp token (with its TSTInfo). It
// parses structurally with encoding/asn1 — it does not verify signatures (Kalkan
// does that). Input is the DER of a CMS SignedData (strip the PEM envelope first).
package cms

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CMS / attribute OIDs (RFC 5652 / 3161).
var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidTimestampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidTSTInfo        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// SignerInfo is the extracted per-signer data.
type SignerInfo struct {
	// SerialNumberHex identifies the signer certificate via the SID
	// (issuerAndSerialNumber); lower-case hex, no leading zeros stripped beyond
	// big.Int's encoding. Empty when the SID is a subjectKeyIdentifier.
	SerialNumberHex       string
	SubjectKeyIDHex       string
	SignatureAlgorithmOID string
	DigestAlgorithmOID    string
	SigningTime           *time.Time
	Timestamp             *Timestamp // nil when the signer carries no TSP token
}

// Timestamp is the parsed TSTInfo of an RFC 3161 timestamp token.
type Timestamp struct {
	Version          int
	Policy           string
	SerialNumberHex  string
	GenTime          *time.Time
	HashAlgorithmOID string
	Hash             []byte
	TSA              string // best-effort text from the tsa GeneralName
}

// ── ASN.1 shapes ──

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedDataRaw struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []signerInfoRaw `asn1:"set"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfoRaw struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tstInfoRaw struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       asn1.RawValue `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// ParseSigners extracts per-signer facts from a CMS SignedData (DER). It returns
// an empty slice (not an error) when the input is not a SignedData, so callers
// can treat parsing as best-effort.
func ParseSigners(der []byte) ([]SignerInfo, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	out := make([]SignerInfo, 0, len(sd.SignerInfos))
	for _, si := range sd.SignerInfos {
		info := SignerInfo{
			SignatureAlgorithmOID: si.SignatureAlgorithm.Algorithm.String(),
			DigestAlgorithmOID:    si.DigestAlgorithm.Algorithm.String(),
		}
		fillSID(&info, si.SID)
		for _, a := range parseAttributes(si.SignedAttrs) {
			if a.Type.Equal(oidSigningTime) {
				if t := parseTime(a.Values.Bytes); t != nil {
					info.SigningTime = t
				}
			}
		}
		for _, a := range parseAttributes(si.UnsignedAttrs) {
			if a.Type.Equal(oidTimestampToken) {
				if ts, err := ParseTimestampToken(a.Values.Bytes); err == nil {
					info.Timestamp = ts
				}
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// ParseTimestampToken parses an RFC 3161 timestamp token (a CMS SignedData whose
// eContent is a TSTInfo).
func ParseTimestampToken(der []byte) (*Timestamp, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	var eci encapContentInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.FullBytes, &eci); err != nil {
		return nil, fmt.Errorf("cms: encapContentInfo: %w", err)
	}
	if !eci.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("cms: not a TSTInfo token")
	}
	// EContent is [0] EXPLICIT OCTET STRING; its content is the TSTInfo DER.
	var octet []byte
	if _, err := asn1.Unmarshal(eci.EContent.Bytes, &octet); err != nil {
		return nil, fmt.Errorf("cms: tst octet: %w", err)
	}
	var tst tstInfoRaw
	if _, err := asn1.Unmarshal(octet, &tst); err != nil {
		return nil, fmt.Errorf("cms: TSTInfo: %w", err)
	}
	gt := tst.GenTime.UTC()
	ts := &Timestamp{
		Version:          tst.Version,
		Policy:           tst.Policy.String(),
		SerialNumberHex:  hexInt(tst.SerialNumber),
		GenTime:          &gt,
		HashAlgorithmOID: tst.MessageImprint.HashAlgorithm.Algorithm.String(),
		Hash:             tst.MessageImprint.HashedMessage,
		TSA:              printableText(tst.TSA.Bytes),
	}
	return ts, nil
}

// parseSignedData unwraps a ContentInfo(signedData) into the SignedData body.
func parseSignedData(der []byte) (*signedDataRaw, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: contentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("cms: not signedData (%s)", ci.ContentType)
	}
	var sd signedDataRaw
	// With an explicit [0] tag, Content.Bytes holds the inner SignedData SEQUENCE.
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		if _, err := asn1.Unmarshal(ci.Content.FullBytes, &sd); err != nil {
			return nil, fmt.Errorf("cms: signedData: %w", err)
		}
	}
	return &sd, nil
}

// parseAttributes splits an IMPLICIT [n] SET OF Attribute into its members.
func parseAttributes(raw asn1.RawValue) []attribute {
	var out []attribute
	b := raw.Bytes
	for len(b) > 0 {
		var a attribute
		rest, err := asn1.Unmarshal(b, &a)
		if err != nil {
			break
		}
		out = append(out, a)
		b = rest
	}
	return out
}

// fillSID pulls the signer identifier: issuerAndSerialNumber (a SEQUENCE) or a
// [0] subjectKeyIdentifier.
func fillSID(info *SignerInfo, sid asn1.RawValue) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		info.SubjectKeyIDHex = strings.ToUpper(hex.EncodeToString(sid.Bytes))
		return
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err == nil {
		info.SerialNumberHex = hexInt(ias.Serial)
	}
}

// parseTime decodes a Time (UTCTime or GeneralizedTime) from raw DER bytes.
func parseTime(b []byte) *time.Time {
	var t time.Time
	if _, err := asn1.Unmarshal(b, &t); err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// hexInt renders a serial number as upper-case hex (matching Kalkan's CERT_SN).
func hexInt(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(n.Bytes()))
}

// printableText best-effort extracts a human-readable token from a GeneralName's
// raw bytes (the tsa field), returning "" when nothing printable is found.
func printableText(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}
