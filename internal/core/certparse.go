package core

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"strings"
	"time"

	"github.com/uelnur/qoltanba/internal/pki"
	"github.com/uelnur/qoltanba/internal/provider"
)

// kalkanTimeLayout is how X509CertificateGetInfo renders validity instants
// (DD.MM.YYYY HH:MM:SS ±HH:MM); the domain normalizes them to time.Time.
const kalkanTimeLayout = "02.01.2006 15:04:05 -07:00"

// oidPattern matches a dotted OID inside a free-text property value.
var oidPattern = regexp.MustCompile(`\d+(?:\.\d+){2,}`)

// parseCertificate turns the driver's flat property set into a structured
// Certificate, derives the RK-specific fields, and best-effort enriches it from
// the DER (AIA/CRL/policies). Missing properties are recorded on w, not fatal.
// der may be nil when the raw bytes are unavailable (enrichment is skipped).
func parseCertificate(props provider.CertProperties, der []byte, prefix string, w *warnings) Certificate {
	get := func(name string) string {
		v, _ := props.Get(name)
		return v
	}

	cert := Certificate{
		Subject: Subject{
			CommonName:       get("SUBJECT_COMMONNAME"),
			LastName:         get("SUBJECT_SURNAME"),
			GivenName:        get("SUBJECT_GIVENNAME"),
			Email:            get("SUBJECT_EMAIL"),
			Organization:     get("SUBJECT_ORG_NAME"),
			OrgUnit:          get("SUBJECT_ORGUNIT_NAME"),
			Country:          get("SUBJECT_COUNTRYNAME"),
			Locality:         get("SUBJECT_LOCALITYNAME"),
			State:            get("SUBJECT_SOPN"),
			BusinessCategory: get("SUBJECT_BC"),
			DomainComponent:  get("SUBJECT_DC"),
			DN:               get("SUBJECT_DN"),
		},
		Issuer: Subject{
			CommonName:   get("ISSUER_COMMONNAME"),
			Organization: get("ISSUER_ORG_NAME"),
			OrgUnit:      get("ISSUER_ORGUNIT_NAME"),
			Country:      get("ISSUER_COUNTRYNAME"),
			Locality:     get("ISSUER_LOCALITYNAME"),
			State:        get("ISSUER_SOPN"),
			DN:           get("ISSUER_DN"),
		},
		SerialNumber:   get("CERT_SN"),
		AuthorityKeyID: get("AUTH_KEY_ID"),
		SubjectKeyID:   get("SUBJ_KEY_ID"),
	}

	deriveSubjectIDs(&cert.Subject, get("SUBJECT_SERIALNUMBER"))
	hasNameOrIIN := cert.Subject.CommonName != "" || cert.Subject.IIN != ""
	cert.OwnerType = string(pki.OwnerTypeFrom(cert.Subject.BIN != "", hasNameOrIIN))

	// Validity.
	cert.NotBefore = parseKalkanTime(get("NOTBEFORE"), prefix+"notBefore", w)
	cert.NotAfter = parseKalkanTime(get("NOTAFTER"), prefix+"notAfter", w)

	// Key usage (full list + simplified kind).
	if ku := get("KEY_USAGE"); ku != "" {
		cert.KeyUsage = strings.Fields(ku)
		cert.KeyUsageKind = simplifyKeyUsage(cert.KeyUsage)
		cert.IsCA = contains(cert.KeyUsage, "keyCertSign")
	}

	// Extended key usage → raw items + derived roles. A CA leaf has no EKU.
	if eku := get("EXT_KEY_USAGE"); eku != "" {
		cert.ExtendedKeyUsage = splitEKU(eku)
		roleOIDs := oidPattern.FindAllString(eku, -1)
		for _, r := range pki.KeyUsersFromEKU(roleOIDs) {
			cert.Roles = append(cert.Roles, string(r))
		}
		cert.IsCA = false
	}

	// Signature algorithm text + OID → key-algorithm family.
	if sa := get("SIGNATURE_ALG"); sa != "" {
		cert.SignatureAlgorithm = strings.TrimSpace(stripParenOID(sa))
		cert.SignatureAlgorithmOID = lastOID(sa)
		cert.KeyAlgorithm = deriveKeyAlgorithm(cert.SignatureAlgorithmOID)
	}

	if pk := get("PUBKEY"); pk != "" {
		if raw, err := base64.StdEncoding.DecodeString(pk); err == nil {
			cert.PublicKey = raw
		}
	}
	if pol := get("POLICIES_ID"); pol != "" {
		cert.PolicyOIDs = oidPattern.FindAllString(pol, -1)
	}

	if len(der) > 0 {
		cert.PEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		enrichFromDER(&cert, der)
	}
	return cert
}

// deriveSubjectIDs pulls IIN/BIN out of their carrier fields and infers gender.
// serial is the raw SUBJECT_SERIALNUMBER value (carries an IIN or a BIN prefix).
func deriveSubjectIDs(s *Subject, serial string) {
	if iin := trimPrefix(serial, pki.IINPrefix); iin != "" {
		s.IIN = iin
		s.Gender = pki.GenderFromIIN(iin)
	}
	// BIN lives in OU, or in serialNumber with a BIN prefix, for legal persons.
	if bin := trimPrefix(s.OrgUnit, pki.BINPrefix); bin != "" {
		s.BIN = bin
	} else if bin := trimPrefix(serial, pki.BINPrefix); bin != "" {
		s.BIN = bin
	}
}

// enrichFromDER adds AIA/CRL/policy data from a DER parse. Best-effort: a parse
// failure leaves the library-sourced fields untouched.
func enrichFromDER(cert *Certificate, der []byte) {
	c, err := x509.ParseCertificate(der)
	if err != nil || c == nil {
		return
	}
	cert.OCSPURLs = mergeUnique(cert.OCSPURLs, c.OCSPServer)
	cert.CAIssuerURLs = mergeUnique(cert.CAIssuerURLs, c.IssuingCertificateURL)
	cert.CRLURLs = mergeUnique(cert.CRLURLs, c.CRLDistributionPoints)
	if cert.AuthorityKeyID == "" && len(c.AuthorityKeyId) > 0 {
		cert.AuthorityKeyID = strings.ToUpper(hex.EncodeToString(c.AuthorityKeyId))
	}
	if cert.SubjectKeyID == "" && len(c.SubjectKeyId) > 0 {
		cert.SubjectKeyID = strings.ToUpper(hex.EncodeToString(c.SubjectKeyId))
	}
	if c.IsCA {
		cert.IsCA = true
	}
	for _, oid := range c.PolicyIdentifiers {
		cert.PolicyOIDs = mergeUnique(cert.PolicyOIDs, []string{oid.String()})
	}
}

// simplifyKeyUsage collapses the key-usage bits into SIGN/AUTH/UNKNOWN for
// parity with the reference. SIGN wins when both patterns match.
func simplifyKeyUsage(bits []string) string {
	has := func(s string) bool { return contains(bits, s) }
	switch {
	case has("digitalSignature") && has("nonRepudiation"):
		return "SIGN"
	case has("digitalSignature") && has("keyEncipherment"):
		return "AUTH"
	default:
		return "UNKNOWN"
	}
}

// deriveKeyAlgorithm maps a certificate signature-algorithm OID to a key family.
func deriveKeyAlgorithm(signOID string) string {
	switch signOID {
	case pki.SignSHA1RSA, pki.SignSHA256RSA:
		return "rsa"
	case pki.SignGOST2015_256:
		return "gost2015-256"
	case pki.SignGOST2015_512:
		return "gost2015-512"
	case "":
		return ""
	default:
		return "gost2004"
	}
}

// parseKalkanTime parses the driver's timestamp format, recording a warning on
// failure. Empty input is silently skipped (an absent optional field).
func parseKalkanTime(v, field string, w *warnings) *time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	t, err := time.Parse(kalkanTimeLayout, v)
	if err != nil {
		w.add(field, "unparseable time: "+v)
		return nil
	}
	t = t.UTC()
	return &t
}

// splitEKU splits the EXT_KEY_USAGE aggregate ("A; B; C") into trimmed items.
func splitEKU(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ";") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// stripParenOID removes a trailing "(oid)" group from a property value.
func stripParenOID(v string) string {
	if i := strings.LastIndex(v, "("); i > 0 {
		return strings.TrimSpace(v[:i])
	}
	return v
}

// lastOID returns the last dotted OID found in v (empty if none).
func lastOID(v string) string {
	all := oidPattern.FindAllString(v, -1)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

// trimPrefix returns the value after a required prefix, or "" if absent.
func trimPrefix(v, prefix string) string {
	v = strings.TrimSpace(v)
	if v == "" || !strings.HasPrefix(v, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(v, prefix))
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// mergeUnique appends items from add not already in base.
func mergeUnique(base, add []string) []string {
	for _, v := range add {
		if v != "" && !contains(base, v) {
			base = append(base, v)
		}
	}
	return base
}
