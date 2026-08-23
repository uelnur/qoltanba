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

import (
	"context"
	"time"
)

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
	// Policy names a signing profile (an ETSI level) instead of assembling the
	// flags that produce it: it resolves Format and the time-stamp default. An
	// explicit Format that contradicts the policy is rejected rather than silently
	// overridden.
	Policy SignaturePolicy
	Format SignatureFormat
	Data   []byte
	// DataRef signs a payload by reference (a local path or a URL) instead of
	// inline Data — for large files. It requires a configured DataResolver and is
	// supported for CMS. When set, Data is ignored.
	DataRef DataRef
	Key     KeySpec

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
	// DataRef supplies the detached source content by reference (path/URL) for a
	// large original, instead of inline Data. Requires a DataResolver; CMS only.
	DataRef  DataRef
	Detached bool
	InputPEM bool

	CheckCertTime  bool
	ExtractContent bool // recover the original content (attached)
	ExtractClaims  bool // populate each signer's OIDC Claims from its certificate
	// Explain adds a step-by-step "why (in)valid" diagnosis to the output
	// (VerifyOutput.Explanation) — a plain-language breakdown for callers without
	// a crypto background. Pure synthesis over the result; no extra work.
	Explain bool
	// Report adds the human-facing verification card (VerifyOutput.Report): who
	// signed, when, with what, and what could be established. Pure synthesis over
	// the result, like Explain; it is also what a verification receipt attests to.
	Report bool
	// Receipt asks the service to sign its verification outcome with its own key
	// (VerifyOutput.Receipt): a machine-checkable attestation the caller can file
	// as audit evidence and verify later against the service's JWKS. It implies
	// building the report, which the receipt attests to.
	Receipt bool
	// TrustedCerts are extra CAs merged with the configured trust-store to build
	// the chain. XML verification requires anchors; CMS works without them.
	TrustedCerts []TrustedCert

	// RevocationCheck controls whether each signer's certificate is checked for
	// revocation as part of verification. Nil means on, which is the default
	// because a verdict that silently omits revocation is the one way this
	// service can report a repudiated signature as good. Set it to false to skip
	// the check (offline verification, or a caller that checks it separately) —
	// the verdict is then indeterminate rather than valid, since the question was
	// left open.
	RevocationCheck *bool
	// RevocationMethod selects OCSP (default) or CRL for that check.
	RevocationMethod ValidationMethod
	// ResponderURL overrides the OCSP responder used by the revocation check.
	ResponderURL string
	// Archive embeds the long-term validation evidence gathered during this
	// verification into the container and returns it (VerifyOutput.Archive), so
	// the archive holds exactly the evidence the verdict was reached on instead
	// of evidence collected by a second, later pass. CMS only; needs the
	// revocation check, which is where the OCSP responses come from.
	Archive bool
}

// RevocationRequested reports whether the revocation check should run. It is on
// unless the caller explicitly turned it off.
func (in VerifyInput) RevocationRequested() bool {
	return in.RevocationCheck == nil || *in.RevocationCheck
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
	// Explanation is the step-by-step "why (in)valid" diagnosis. Set only when the
	// request asks for it (VerifyInput.Explain).
	Explanation *Diagnosis `json:"explanation,omitempty"`
	// Report is the human-facing verification card. Set only when the request asks
	// for it (VerifyInput.Report).
	Report *VerificationReport `json:"report,omitempty"`
	// Receipt is the service's signed attestation of this verification (compact
	// JWS). Set only when the request asks for it (VerifyInput.Receipt) and a
	// receipt signer is configured.
	Receipt string `json:"receipt,omitempty"`
	// Archive is the container with this verification's evidence embedded
	// (CAdES-LT). Set only when the request asks for it (VerifyInput.Archive).
	Archive *ArchiveOutput `json:"archive,omitempty"`
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
	// Algorithm classifies the certificate's cryptographic generation and, when it
	// is not the current one, says what to reissue it as.
	Algorithm AlgorithmInfo `json:"algorithm"`
	Claims    *Claims       `json:"claims,omitempty"` // set when ExtractClaims requested
	Warnings  []Warning     `json:"warnings,omitempty"`
	LibError  *LibError     `json:"libError,omitempty"`
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
	Revoked bool `json:"revoked"`
	// Determinate reports whether the status was actually established. A check
	// that could not be completed also leaves Revoked false, and reading that as
	// "not revoked" is how an unreachable responder turns into a good verdict.
	Determinate    bool             `json:"determinate"`
	Method         ValidationMethod `json:"method,omitempty"`
	RevocationTime *time.Time       `json:"revocationTime,omitempty"`
	Reason         string           `json:"reason,omitempty"`
	CheckedAt      *time.Time       `json:"checkedAt,omitempty"`
	ThisUpdate     *time.Time       `json:"thisUpdate,omitempty"`
	NextUpdate     *time.Time       `json:"nextUpdate,omitempty"`
	ProducedAt     *time.Time       `json:"producedAt,omitempty"` // OCSP producedAt
	LibError       *LibError        `json:"libError,omitempty"`
}

// AuditSink records what the service did, for a tamper-evident operational
// journal. The domain declares the port and reports facts; where and how they are
// stored is the sink's business. A sink that fails must not fail the operation —
// an unrecorded check is a gap in the journal, not a reason to refuse work.
type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent)
}

// AuditEvent is one recorded operation.
type AuditEvent struct {
	Op      string // sign | verify | validate
	Subject string // what was operated on: a digest, not the content itself
	Signer  string // whose signature was involved (IIN/BIN)
	Outcome string // valid | invalid | ok | error
	Detail  string
}

// OCSPCache caches revocation answers so repeated checks of one certificate do
// not each reach the responder. The domain declares the port; internal/ocspcache
// implements it. Lookup returning false simply means "ask the library".
type OCSPCache interface {
	Lookup(certDER []byte, responder string) (OCSPAnswer, bool)
	Store(certDER []byte, responder string, answer OCSPAnswer)
}

// OCSPAnswer is one cached revocation answer: the verdict plus the raw response,
// kept so a caller asking for the response gets the responder's own bytes.
type OCSPAnswer struct {
	Revoked        bool
	Reason         string
	RevocationTime *time.Time
	ThisUpdate     *time.Time
	NextUpdate     *time.Time
	ProducedAt     *time.Time
	Response       []byte
}

// TrustedCert is a CA certificate to load into the trust store for chain building.
type TrustedCert struct {
	Cert         []byte `json:"cert"`
	Intermediate bool   `json:"intermediate,omitempty"` // true for intermediate, false for a root
}
