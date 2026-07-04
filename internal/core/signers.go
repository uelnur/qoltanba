package core

import (
	"strings"

	"github.com/uelnur/qoltanba/internal/cms"
	"github.com/uelnur/qoltanba/internal/pki"
)

// cmsSignersBySerial parses a CMS SignedData and indexes its signer facts by
// normalized certificate serial. Empty for non-CMS or unparseable input — the
// enrichment is best-effort.
func cmsSignersBySerial(format SignatureFormat, signature []byte) map[string]cms.SignerInfo {
	if format != FormatCMS || len(signature) == 0 {
		return nil
	}
	parsed, err := cms.ParseSigners(toDER(signature, EncodingPEM))
	if err != nil {
		return nil
	}
	out := make(map[string]cms.SignerInfo, len(parsed))
	for _, si := range parsed {
		if si.SerialNumberHex != "" {
			out[normHex(si.SerialNumberHex)] = si
		}
	}
	return out
}

// normHex normalizes a hex serial for matching: upper-case, leading zeros
// trimmed (Kalkan's CERT_SN and big.Int encodings can differ on padding).
func normHex(h string) string {
	h = strings.ToUpper(strings.TrimSpace(h))
	h = strings.TrimLeft(h, "0")
	if h == "" {
		return "0"
	}
	return h
}

// timestampFromCMS maps a parsed TSTInfo to the contract Timestamp, resolving the
// hash-algorithm OID to a name.
func timestampFromCMS(t *cms.Timestamp) *Timestamp {
	hashName := pki.HashNameForOID(t.HashAlgorithmOID)
	if hashName == "" {
		hashName = t.HashAlgorithmOID
	}
	return &Timestamp{
		SerialNumber:  t.SerialNumberHex,
		GenTime:       t.GenTime,
		Policy:        t.Policy,
		TSA:           t.TSA,
		HashAlgorithm: hashName,
		Hash:          t.Hash,
	}
}

// sigAlgName maps a signature-algorithm OID to a friendly name, falling back to
// the OID string.
func sigAlgName(oid string) string {
	switch oid {
	case pki.SignGOST2015_256:
		return "GOST R 34.10-2015 256"
	case pki.SignGOST2015_512:
		return "GOST R 34.10-2015 512"
	case pki.SignSHA256RSA:
		return "SHA256withRSA"
	case pki.SignSHA1RSA:
		return "SHA1withRSA"
	case "":
		return ""
	default:
		if n := pki.Name(oid); n != "" {
			return n
		}
		return oid
	}
}
