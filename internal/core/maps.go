package core

import (
	"encoding/base64"
	"encoding/pem"

	"github.com/uelnur/qoltanba/internal/provider"
)

// certFormat maps a domain encoding to the driver's CertFormat.
func certFormat(e CertEncoding) provider.CertFormat {
	switch e {
	case EncodingDER:
		return provider.CertDER
	case EncodingB64:
		return provider.CertB64
	default:
		return provider.CertPEM
	}
}

// validationMethod maps a domain method to the driver's ValidationMethod.
func validationMethod(m ValidationMethod) provider.ValidationMethod {
	if m == MethodCRL {
		return provider.ValidateCRL
	}
	return provider.ValidateOCSP
}

// toDER normalizes certificate bytes to raw DER for x509 enrichment. It returns
// nil when the input cannot be decoded, so enrichment is simply skipped.
func toDER(raw []byte, enc CertEncoding) []byte {
	switch enc {
	case EncodingDER:
		return raw
	case EncodingB64:
		if d, err := base64.StdEncoding.DecodeString(string(raw)); err == nil {
			return d
		}
		return nil
	default:
		if block, _ := pem.Decode(raw); block != nil {
			return block.Bytes
		}
		// Fall back to treating the bytes as DER already.
		return raw
	}
}
