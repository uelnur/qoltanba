package provider

import "time"

// StorageType is the key storage kind, an abstraction over Kalkan's KCST_*
// codes. The driver maps it to native values; callers work with meaning, not
// hex.
type StorageType int

const (
	StoragePKCS12   StorageType = iota + 1 // .p12/.pfx file
	StorageKZIDCard                        // Kazakhstan ID card
	StorageKaztoken                        // KAZTOKEN
	StorageEToken72K
	StorageJaCarta
	StorageX509Cert
	StorageAKey
	StorageEToken5110
)

// CertFormat is the certificate encoding on input/output.
type CertFormat int

const (
	CertPEM CertFormat = iota + 1 // -----BEGIN CERTIFICATE-----
	CertDER                       // raw DER
	CertB64                       // base64 without the PEM envelope
)

// ValidationMethod is how certificate status is checked.
type ValidationMethod int

const (
	ValidateOCSP ValidationMethod = iota + 1
	ValidateCRL
	// ValidateNone builds and cryptographically verifies the chain against the
	// loaded trust anchors WITHOUT a revocation check (KC_USE_NOTHING) — offline,
	// and works for GOST which Go cannot verify.
	ValidateNone
)

// CertStatus is the outcome of a revocation check.
type CertStatus int

const (
	StatusUnknown CertStatus = iota
	StatusGood
	StatusRevoked
)

// KeyRef points to key material for a signing operation. The driver loads the
// key for the duration of the call. Extensible toward the domain's KeySource
// (inline/path/token) without changing signatures.
type KeyRef struct {
	Storage  StorageType
	Path     string // container path (a .p12 file for StoragePKCS12)
	Password string // container password; callers redact it from logs
}

// SignRequest is a signing request. XML has its own SignXMLRequest below.
type SignRequest struct {
	Key  KeyRef
	Data []byte
	// Path, when set, makes the library read the content from this file directly
	// (KC_IN_FILE) instead of Data — the driver streams it, nothing is buffered in
	// Go. Data is ignored when Path is set.
	Path     string
	Detached bool // detach the content from the signature (KC_DETACHED_DATA)
	InputPEM bool // input data is already PEM
	OutPEM   bool // output as PEM (otherwise DER)
	// CheckCertTime=false signs even with an expired certificate
	// (KC_NOCHECKCERTTIME). The zero value therefore skips the time check — a
	// deliberate default for batch/archival work; set it when a strict check is
	// required.
	CheckCertTime bool
	WithTimestamp bool   // add a TSA timestamp (KC_WITH_TIMESTAMP)
	TSAURL        string // TSA address (empty uses the NUC default)
	// ExistingSignature co-signs: add this signer to an already-signed CMS
	// (passed as inSign). Empty means the first signature.
	ExistingSignature []byte
	// TrustedCerts are CA certificates loaded into the store before signing. With
	// CheckCertTime the library validates the signer's chain to a trusted root, so
	// the issuing CA(s) must be present — a leaf-only key store alone fails with
	// KCR "load root or intermediate certificate" (0x08F00042).
	TrustedCerts []TrustedCert
}

// SignXMLRequest is an XML signing request (XMLDSig).
type SignXMLRequest struct {
	Key           KeyRef
	XML           []byte
	CheckCertTime bool
	WithTimestamp bool
	TSAURL        string
	NodeID        string // id of the node to sign (empty signs the whole document)
	ParentNode    string
	ParentNS      string
	TrustedCerts  []TrustedCert // CA chain loaded before signing (see SignRequest)
}

// SignResult is the output of a signing operation.
type SignResult struct {
	Signature []byte // CMS/XML/WSSE in the requested encoding
}

// SignWSSERequest signs a SOAP envelope per WS-Security (SignWSSE). Verify it
// with VerifyXML, since WSSE is XML.
type SignWSSERequest struct {
	Key           KeyRef
	XML           []byte
	NodeID        string // id of the signed node (wsu:Id), e.g. "Body"
	CheckCertTime bool
	WithTimestamp bool
	TSAURL        string
	TrustedCerts  []TrustedCert // CA chain loaded before signing (see SignRequest)
}

// ExportResult is the owner certificate from a key container (pkcs12/info) plus
// the alias returned by KC_LoadKeyStore (empty on the NUC test keys).
type ExportResult struct {
	Cert  []byte
	Alias string
}

// HashRequest computes a digest (HashData). Algorithm is a Kalkan algorithm
// name (e.g. "GOST34311" for the GOST family).
type HashRequest struct {
	Algorithm string
	Data      []byte
}

// HashResult is the raw digest.
type HashResult struct {
	Hash []byte
}

// SignHashRequest signs a precomputed digest (SignHash). Used for streaming
// signatures over large data and as the basis for GOST JWT.
type SignHashRequest struct {
	Key           KeyRef
	Hash          []byte
	OutPEM        bool
	CheckCertTime bool
}

// VerifyRequest verifies a CMS or XML signature.
type VerifyRequest struct {
	Signature []byte
	Data      []byte // source data for detached CMS; nil for attached/XML
	// Path, when set, makes the library read the detached source content from this
	// file (KC_IN_FILE) instead of Data — no buffering in Go. Data is ignored when
	// Path is set.
	Path          string
	Detached      bool
	InputPEM      bool
	OutPEM        bool
	CheckCertTime bool
	SignerIndex   int // 0-based signature index for signer extraction
	// TrustedCerts are the CAs (root/intermediate) used to build the chain. XML
	// verification requires them (otherwise KCR_LOADTRUSTEDCERTSERR); CMS
	// verification works without them.
	TrustedCerts []TrustedCert
}

// VerifyResult is the exhaustive verification outcome: validity plus everything
// that could be extracted. Fields the library did not return stay zero.
type VerifyResult struct {
	Valid      bool      // native check returned rc==0
	Info       string    // outVerifyInfo (an OpenSSL string; zeros mean no error)
	Content    []byte    // recovered/verified content (attached)
	SignerCert []byte    // first signer certificate (PEM), for convenience
	Signers    [][]byte  // all signer certificates (multi-signature), PEM
	Timestamp  time.Time // timestamp from the signature, if present
	RawCode    uint32    // raw rc for diagnostics
}

// CertField is one certificate property (X509CertificateGetInfo).
type CertField struct {
	ID    uint32 // propId (0x08xx)
	Name  string // human-readable property name (SUBJECT_COMMONNAME, …)
	Value string // text value (already NUL-trimmed, without the "name=" prefix)
	Raw   []byte // raw bytes for non-printable values (keys, ids)
	OK    bool   // property present (rc==0); false means no value
}

// CertProperties is every extracted certificate property. Interpretation
// (IIN/BIN/role/gender by OID) is the domain's job; the driver returns the raw
// set.
type CertProperties struct {
	Fields []CertField
}

// Get returns a field value by name and whether it is present.
func (c CertProperties) Get(name string) (string, bool) {
	for _, f := range c.Fields {
		if f.Name == name {
			return f.Value, f.OK
		}
	}
	return "", false
}

// ValidateRequest checks certificate status (OCSP/CRL) and builds chain trust
// from the given CAs.
type ValidateRequest struct {
	Cert      []byte
	Format    CertFormat
	Method    ValidationMethod
	Path      string    // OCSP responder URL or CRL file path
	CheckTime time.Time // the instant to validate against
	WantOCSP  bool      // return the raw OCSP response (KC_GET_OCSP_RESPONSE)
	// TrustedCerts are CA/intermediate certificates (PEM/DER) to load before the
	// check.
	TrustedCerts []TrustedCert
}

// TrustedCert is a trusted CA to load into an instance's trust store.
type TrustedCert struct {
	Cert         []byte
	Intermediate bool // true for intermediate, false for root
}

// ValidateResult is the status-check outcome.
type ValidateResult struct {
	Status       CertStatus
	Info         string // native check outInfo text
	OCSPResponse []byte // raw OCSP response, if requested
	RawCode      uint32
}

// SelfTestResult is the outcome of the mandatory smoke self-test: it proves the
// loaded library not only links but computes a known digest correctly. The
// driver computes a digest with the library and cross-checks it against Go's
// own implementation of the same algorithm, so no hard-coded reference constant
// is needed. A cgo-free value type: the compatibility layer consumes it.
type SelfTestResult struct {
	Ran       bool   // the test executed (the digest primitive was available)
	OK        bool   // the library's digest matched the reference
	Algorithm string // the digest algorithm exercised (e.g. "SHA256")
	Detail    string // human-readable outcome (match, mismatch, or skip reason)
}

// Capabilities maps the operations available in the loaded library version. The
// Kalkan function table grows between versions; the driver marks unavailable
// methods false and a call returns ErrUnsupported.
type Capabilities struct {
	Version    string // detected library version (from file name/config)
	PoolSize   int    // number of isolated instances in the pool
	SignCMS    bool
	VerifyCMS  bool
	SignXML    bool
	VerifyXML  bool
	CertInfo   bool
	Validate   bool
	Timestamp  bool // TSA support
	ZipSign    bool // ZipConSign/ZipConVerify (newer versions)
	WSSE       bool // SignWSSE
	Hash       bool // HashData + SignHash (needed for JWT/detached hash)
	ExportCert bool // X509ExportCertificateFromStore
}
