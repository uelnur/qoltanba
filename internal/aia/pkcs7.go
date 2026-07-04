package aia

import (
	"crypto/x509"
	"encoding/asn1"
)

// oidSignedData is PKCS#7 SignedData (RFC 2315).
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// contentInfo is the PKCS#7 outer wrapper.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData captures only what a certs-only bundle needs: the certificates
// field. Remaining fields are parsed as raw to satisfy the SEQUENCE shape.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

// parsePKCS7Certs extracts certificates from a PKCS#7 SignedData bundle (the
// common .p7c form AIA "CA Issuers" endpoints serve). It returns nil when der is
// not a certs-bearing SignedData.
func parsePKCS7Certs(der []byte) []*x509.Certificate {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil
	}
	// With an explicit [0] tag, Content.Bytes holds the inner SignedData SEQUENCE
	// (full TLV); fall back to FullBytes for decoders that populate it instead.
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		if _, err := asn1.Unmarshal(ci.Content.FullBytes, &sd); err != nil {
			return nil
		}
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil
	}
	// Certificates.Bytes is the content of the [0] IMPLICIT field: one or more
	// concatenated X.509 certificate SEQUENCEs. ParseCertificates handles the run.
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil
	}
	return certs
}
