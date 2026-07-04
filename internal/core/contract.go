// Package core is the domain layer: transport-independent orchestration over the
// Provider port. It owns the request/response contract that every transport maps
// to, resolves keys through KeySource, calls the driver, and assembles the
// exhaustive best-effort result (parsing certificate properties and deriving
// IIN/BIN/role/gender). It knows nothing about HTTP, gRPC, proto or cgo.
//
// The types here are the domain's own contract, deliberately decoupled from the
// draft api/native.proto: proto is one serialization a transport may adopt later,
// not the source of truth the domain binds to. Binary payloads are plain []byte
// and times are time.Time; encoding (base64/PEM, RFC3339) is a transport concern.
package core

import "time"

// SignatureFormat selects the container kind for a sign or verify operation.
type SignatureFormat string

const (
	FormatCMS  SignatureFormat = "cms"  // CMS/PKCS#7
	FormatXML  SignatureFormat = "xml"  // XMLDSig
	FormatWSSE SignatureFormat = "wsse" // WS-Security (verified as XML)
)

// Valid reports whether f is a known format.
func (f SignatureFormat) Valid() bool {
	switch f {
	case FormatCMS, FormatXML, FormatWSSE:
		return true
	default:
		return false
	}
}

// LibError is the crypto-core error, kept separate from the business outcome: an
// operation can fail at the library while the request itself was well-formed. It
// carries the raw KCR_* code and the library's last error text (Code/Text, for
// diagnosis) plus a friendly rendering (Key/Message/Action, from the error
// catalog) so a caller without a crypto background can act on it. Key is a stable
// locale-independent identifier; Message/Action are English (see provider.Explain).
type LibError struct {
	Code    string `json:"code"` // e.g. "0x08F0001C"
	Text    string `json:"text,omitempty"`
	Key     string `json:"key,omitempty"`     // stable catalog id, e.g. "cert.expired"
	Message string `json:"message,omitempty"` // plain-language description
	Action  string `json:"action,omitempty"`  // suggested remedy
}

// Warning records a best-effort extraction miss: a field the library could not
// return. The operation still succeeds; the field is simply absent. Reason
// carries the KCR_* code or an explanation.
type Warning struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// SignInput is a signing request. One call signs one item; batching is a higher
// layer over this.
type SignInput struct {
	Format SignatureFormat
	Data   []byte
	Key    KeySpec

	Detached bool
	// WithTimestamp adds an RFC 3161 TSA timestamp (CAdES-T). Tri-state: nil uses
	// the service default (config sign.default-timestamp); a non-nil value
	// overrides it per request.
	WithTimestamp *bool
	TSAURL        string // empty uses the NUC default responder
	// NoCheckCertTime signs even with an expired certificate. The domain default
	// (false) enforces the time check — the safe default — and inverts the
	// driver's permissive zero value at this boundary.
	NoCheckCertTime bool
	InputPEM        bool
	OutputPEM       bool

	// TrustedCerts are CA certificates (roots/intermediates) loaded into the store
	// before signing so the time check can anchor the signer's chain. They are
	// merged with the service trust store; ignored when NoCheckCertTime is set.
	TrustedCerts []TrustedCert

	// XML/WSSE node targeting (ignored for CMS).
	NodeID     string
	ParentNode string
	ParentNS   string

	// ExistingSignature co-signs: add this signer to an already-signed container.
	// Empty means a first signature.
	ExistingSignature []byte
}

// SignOutput is the signing result. When a timestamp was added, the parsed TSP
// token is echoed (CMS) so callers need not re-verify to see it.
type SignOutput struct {
	Signature  []byte          `json:"signature,omitempty"`
	Format     SignatureFormat `json:"format,omitempty"`
	Timestamp  *Timestamp      `json:"timestamp,omitempty"` // parsed TSP (CMS only); nil otherwise
	CAdESLevel string          `json:"cadesLevel,omitempty"`
	LibError   *LibError       `json:"libError,omitempty"`
}

// VerifyInput verifies a CMS/XML/WSSE signature and extracts everything available.
type VerifyInput struct {
	Format    SignatureFormat
	Signature []byte
	Data      []byte // source data for detached CMS; nil for attached/XML
	Detached  bool
	InputPEM  bool

	CheckCertTime  bool
	ExtractContent bool // recover the original content (attached)
	ExtractClaims  bool // populate each signer's OIDC Claims from its certificate
	// TrustedCerts are extra CAs merged with the configured trust-store to build
	// the chain. XML verification requires anchors; CMS works without them.
	TrustedCerts []TrustedCert
}

// VerifyOutput is the exhaustive verification outcome.
type VerifyOutput struct {
	Valid    bool            `json:"valid"`
	Format   SignatureFormat `json:"format,omitempty"`
	Detached bool            `json:"detached"`
	Signers  []Signer        `json:"signers,omitempty"`
	Content  []byte          `json:"content,omitempty"` // recovered original, if attached and requested
	Warnings []Warning       `json:"warnings,omitempty"`
	LibError *LibError       `json:"libError,omitempty"`
}

// ExtractInput recovers the original content from an attached signature.
type ExtractInput struct {
	Format    SignatureFormat
	Signature []byte
	Data      []byte
}

// ExtractOutput carries the recovered content.
type ExtractOutput struct {
	Content  []byte    `json:"content,omitempty"`
	Detached bool      `json:"detached"`
	LibError *LibError `json:"libError,omitempty"`
}

// CertInfoInput fully parses a certificate, optionally building/validating the
// chain.
type CertInfoInput struct {
	Cert   []byte
	Key    KeySpec // when set, the owner certificate is exported from the key store
	Format CertEncoding

	BuildChain    bool
	Validate      bool
	ExtractClaims bool // populate Claims from the parsed certificate
	Method        ValidationMethod
	TrustedCerts  []TrustedCert
}

// CertInfoOutput is the parsed certificate plus optional chain.
type CertInfoOutput struct {
	Certificate Certificate   `json:"certificate"`
	Chain       []Certificate `json:"chain,omitempty"`
	Claims      *Claims       `json:"claims,omitempty"` // set when ExtractClaims requested
	Warnings    []Warning     `json:"warnings,omitempty"`
	LibError    *LibError     `json:"libError,omitempty"`
}

// ValidateInput checks a certificate's revocation status and chain trust.
type ValidateInput struct {
	Cert         []byte
	Format       CertEncoding
	Method       ValidationMethod
	CheckTime    time.Time // zero means now
	WantOCSP     bool
	TrustedCerts []TrustedCert
	// ResponderURL overrides the OCSP responder (empty uses the NUC default).
	ResponderURL string
	// CRL is the CRL data for Method=CRL (DER or PEM). Kalkan validates against
	// it; the domain also parses it for thisUpdate/nextUpdate/revocation entry.
	CRL []byte
}

// ValidateOutput is the status-check outcome.
type ValidateOutput struct {
	Status       RevocationStatus `json:"status"`
	Info         string           `json:"info,omitempty"`
	OCSPResponse []byte           `json:"ocspResponse,omitempty"`
	Warnings     []Warning        `json:"warnings,omitempty"`
	LibError     *LibError        `json:"libError,omitempty"`
}

// CertEncoding is the certificate encoding on input.
type CertEncoding string

const (
	EncodingPEM CertEncoding = "pem"
	EncodingDER CertEncoding = "der"
	EncodingB64 CertEncoding = "base64"
)

// ValidationMethod selects the revocation-check mechanism.
type ValidationMethod string

const (
	MethodOCSP ValidationMethod = "ocsp"
	MethodCRL  ValidationMethod = "crl"
)

// RevocationStatus is the revocation outcome for a certificate. Time fields
// beyond CheckedAt come from parsing the OCSP response / CRL (best-effort).
type RevocationStatus struct {
	Revoked        bool             `json:"revoked"`
	Method         ValidationMethod `json:"method,omitempty"`
	RevocationTime *time.Time       `json:"revocationTime,omitempty"`
	Reason         string           `json:"reason,omitempty"`
	CheckedAt      *time.Time       `json:"checkedAt,omitempty"`
	ThisUpdate     *time.Time       `json:"thisUpdate,omitempty"`
	NextUpdate     *time.Time       `json:"nextUpdate,omitempty"`
	ProducedAt     *time.Time       `json:"producedAt,omitempty"` // OCSP producedAt
	LibError       *LibError        `json:"libError,omitempty"`
}

// TrustedCert is a CA certificate to load into the trust store for chain building.
type TrustedCert struct {
	Cert         []byte `json:"cert"`
	Intermediate bool   `json:"intermediate,omitempty"` // true for intermediate, false for a root
}
