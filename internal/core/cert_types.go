package core

import "time"

// Subject (or issuer) distinguished-name fields, plus the RK-specific derived
// identifiers. Empty fields were absent in the certificate.
type Subject struct {
	CommonName       string `json:"commonName,omitempty"`
	LastName         string `json:"lastName,omitempty"`  // SURNAME
	GivenName        string `json:"givenName,omitempty"` // GIVENNAME (имя/отчество)
	Email            string `json:"email,omitempty"`
	Organization     string `json:"organization,omitempty"`
	OrgUnit          string `json:"orgUnit,omitempty"` // carries BIN for legal persons
	Country          string `json:"country,omitempty"`
	Locality         string `json:"locality,omitempty"`
	State            string `json:"state,omitempty"` // SOPN
	BusinessCategory string `json:"businessCategory,omitempty"`
	DomainComponent  string `json:"domainComponent,omitempty"`
	DN               string `json:"dn,omitempty"` // raw aggregate DN

	// Derived (computed by the domain, not stored in the certificate).
	IIN    string `json:"iin,omitempty"`
	BIN    string `json:"bin,omitempty"`
	Gender string `json:"gender,omitempty"` // MALE | FEMALE | NONE (from IIN)
}

// Certificate is the exhaustive parsed view of one X.509 certificate: fields the
// library returns plus fields the domain derives. Absent optional fields stay
// zero; a missing property is recorded as a Warning on the enclosing response,
// never an error.
type Certificate struct {
	Subject Subject `json:"subject"`
	Issuer  Subject `json:"issuer"`

	SerialNumber string     `json:"serialNumber,omitempty"` // HEX
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`

	SignatureAlgorithm    string `json:"signatureAlgorithm,omitempty"` // human text
	SignatureAlgorithmOID string `json:"signatureAlgorithmOid,omitempty"`
	KeyAlgorithm          string `json:"keyAlgorithm,omitempty"` // rsa | gost2004 | gost2015-256/512
	PublicKey             []byte `json:"publicKey,omitempty"`    // DER SubjectPublicKeyInfo
	AuthorityKeyID        string `json:"authorityKeyId,omitempty"`
	SubjectKeyID          string `json:"subjectKeyId,omitempty"`

	KeyUsage         []string `json:"keyUsage,omitempty"`         // full bit list
	KeyUsageKind     string   `json:"keyUsageKind,omitempty"`     // SIGN | AUTH | UNKNOWN
	ExtendedKeyUsage []string `json:"extendedKeyUsage,omitempty"` // texts + OIDs, raw
	PolicyOIDs       []string `json:"policyOids,omitempty"`

	// RK-specific derived classification.
	OwnerType string   `json:"ownerType,omitempty"` // INDIVIDUAL | LEGAL_PERSON | INFOSYSTEM | UNKNOWN
	Roles     []string `json:"roles,omitempty"`     // keyUser roles from EKU role-OIDs

	// AIA / distribution points (best-effort from a DER parse).
	CAIssuerURLs []string `json:"caIssuerUrls,omitempty"`
	OCSPURLs     []string `json:"ocspUrls,omitempty"`
	CRLURLs      []string `json:"crlUrls,omitempty"`

	IsCA bool   `json:"isCa,omitempty"` // keyCertSign + no EKU
	PEM  []byte `json:"pem,omitempty"`
}

// Signer is one signature's signer view: its certificate, chain and per-signer
// validity/timestamp. The array index carries no meaning (it is not the signing
// order and differs between CMS and XML).
type Signer struct {
	Certificate        Certificate   `json:"certificate"`
	Chain              []Certificate `json:"chain,omitempty"`
	Valid              bool          `json:"valid"`
	SigningTime        *time.Time    `json:"signingTime,omitempty"`
	SignatureAlgorithm string        `json:"signatureAlgorithm,omitempty"`
	Timestamp          *Timestamp    `json:"timestamp,omitempty"`

	ChainComplete    bool `json:"chainComplete"`
	TrustAnchorFound bool `json:"trustAnchorFound"`
	// ChainSignaturesVerified is true when Kalkan cryptographically validated the
	// chain (KC_USE_NOTHING) against the anchors — the GOST-capable check Go
	// cannot do. Only set when chain verification is enabled.
	ChainSignaturesVerified bool   `json:"chainSignaturesVerified"`
	CAdESLevel              string `json:"cadesLevel,omitempty"` // BES | T
	VerifyInfo              string `json:"verifyInfo,omitempty"` // raw outVerifyInfo
}

// Timestamp is a TSP token summary attached to a signature.
type Timestamp struct {
	SerialNumber  string     `json:"serialNumber,omitempty"`
	GenTime       *time.Time `json:"genTime,omitempty"`
	Policy        string     `json:"policy,omitempty"`
	TSA           string     `json:"tsa,omitempty"`
	HashAlgorithm string     `json:"hashAlgorithm,omitempty"`
	Hash          []byte     `json:"hash,omitempty"`
}
