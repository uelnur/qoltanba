package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// maxChainDepth bounds the issuer walk, guarding against loops in a malformed
// certificate set and capping AIA fetch hops.
const maxChainDepth = 16

// IssuerFetcher retrieves the issuer certificate of cert (DER in, DER out) from
// its Authority Information Access "CA Issuers" URL. The domain declares the
// port; infrastructure (internal/aia) implements it over HTTP. It returns false
// when the issuer cannot be fetched. Fetched issuers are added to the chain but
// are not trust anchors unless they also appear in the configured trust store.
type IssuerFetcher interface {
	FetchIssuer(ctx context.Context, cert []byte) ([]byte, bool)
}

// buildChain assembles the certificate chain for a leaf by walking issuer links
// through the trusted set (roots + intermediates the consumer supplied) and,
// when a fetcher is given, downloading missing issuers via AIA. Issuer selection
// prefers a candidate whose public key actually verifies the signature (for
// algorithms Go supports, e.g. RSA); GOST links, which Go cannot verify, fall
// back to key-id/subject matching. Kalkan verifies the signature itself — this
// reports how far the chain reaches and whether it lands on a configured anchor.
//
// It returns the chain (leaf first, CA nodes after), whether it reached a
// self-signed root (complete), and whether any node is a configured anchor
// (anchored). leafDER may be nil, in which case no chain is built.
func buildChain(ctx context.Context, leafFull Certificate, leafDER []byte, trusted []TrustedCert, fetcher IssuerFetcher) (chain []Certificate, complete, anchored bool) {
	if len(leafDER) == 0 {
		return nil, false, false
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || leaf == nil {
		return nil, false, false
	}

	// Candidate issuers and the anchor lookup (by DER) for the trust decision.
	candidates := make([]*x509.Certificate, 0, len(trusted))
	anchorDERs := make(map[string]bool, len(trusted))
	for _, tc := range trusted {
		der := toDER(tc.Cert, EncodingPEM)
		if len(der) == 0 {
			continue
		}
		if c, err := x509.ParseCertificate(der); err == nil && c != nil {
			candidates = append(candidates, c)
			anchorDERs[string(der)] = true
		}
	}

	chain = []Certificate{leafFull}
	if anchorDERs[string(leafDER)] {
		anchored = true
	}

	current := leaf
	seen := map[string]bool{string(leaf.RawSubject): true}
	for depth := 0; depth < maxChainDepth; depth++ {
		if isSelfIssued(current) {
			complete = true
			break
		}
		issuer := findIssuer(current, candidates)
		if issuer == nil && fetcher != nil {
			issuer = fetchIssuer(ctx, current, fetcher)
		}
		if issuer == nil {
			break
		}
		if seen[string(issuer.RawSubject)] {
			break // cycle guard
		}
		seen[string(issuer.RawSubject)] = true

		der := issuer.Raw
		node := certFromX509(issuer, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		chain = append(chain, node)
		if anchorDERs[string(der)] {
			anchored = true
		}
		current = issuer
	}
	return chain, complete, anchored
}

// fetchIssuer downloads and parses current's issuer via the fetcher.
func fetchIssuer(ctx context.Context, current *x509.Certificate, fetcher IssuerFetcher) *x509.Certificate {
	der, ok := fetcher.FetchIssuer(ctx, current.Raw)
	if !ok || len(der) == 0 {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || c == nil {
		return nil
	}
	// The fetched cert must actually be the issuer (subject matches, and the
	// signature verifies where Go can check it).
	if !bytes.Equal(current.RawIssuer, c.RawSubject) || !issues(current, c) {
		return nil
	}
	return c
}

// findIssuer returns the best candidate whose subject issued current: a
// signature-verified match wins, then an authority-key-id match, then a plain
// subject-name match. A candidate whose signature explicitly fails is rejected.
func findIssuer(current *x509.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	var byKeyID, byName *x509.Certificate
	for _, c := range candidates {
		if !bytes.Equal(current.RawIssuer, c.RawSubject) || !issues(current, c) {
			continue
		}
		if err := current.CheckSignatureFrom(c); err == nil {
			return c // cryptographically confirmed issuer
		}
		if len(current.AuthorityKeyId) > 0 && bytes.Equal(current.AuthorityKeyId, c.SubjectKeyId) {
			if byKeyID == nil {
				byKeyID = c
			}
		} else if byName == nil {
			byName = c
		}
	}
	if byKeyID != nil {
		return byKeyID
	}
	return byName
}

// issues reports whether cand can be current's issuer as far as Go can tell:
// true when the signature verifies or when the algorithm is unsupported (GOST —
// undecidable in Go, so not rejected); false when the signature is definitively
// wrong.
func issues(current, cand *x509.Certificate) bool {
	err := current.CheckSignatureFrom(cand)
	if err == nil {
		return true
	}
	// Unsupported algorithm (GOST) → cannot decide here; accept structurally.
	return errors.Is(err, x509.ErrUnsupportedAlgorithm) || isUnsupportedAlgo(err)
}

// isUnsupportedAlgo matches the unsupported-algorithm error by content, covering
// x509 variants that do not wrap ErrUnsupportedAlgorithm.
func isUnsupportedAlgo(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unsupported")
}

// isSelfIssued reports whether a certificate is its own issuer.
func isSelfIssued(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject)
}

// nodeIsRoot reports whether a PEM chain node is a self-issued root (loaded as a
// CA anchor rather than an intermediate).
func nodeIsRoot(pemBytes []byte) bool {
	c, err := x509.ParseCertificate(toDER(pemBytes, EncodingPEM))
	return err == nil && c != nil && isSelfIssued(c)
}

// certFromX509 builds a lightweight Certificate view for a CA node from a parsed
// certificate. RK-specific derivation (IIN/roles) does not apply to CA nodes, so
// this avoids an extra Kalkan property call.
func certFromX509(c *x509.Certificate, pemBytes []byte) Certificate {
	nb, na := c.NotBefore.UTC(), c.NotAfter.UTC()
	cert := Certificate{
		Subject:      subjectFromName(c.Subject.String(), c),
		Issuer:       issuerFromCert(c),
		SerialNumber: strings.ToUpper(hex.EncodeToString(c.SerialNumber.Bytes())),
		NotBefore:    &nb,
		NotAfter:     &na,
		IsCA:         c.IsCA,
		KeyUsage:     keyUsageStrings(c.KeyUsage),
		PEM:          pemBytes,
	}
	if len(c.SubjectKeyId) > 0 {
		cert.SubjectKeyID = strings.ToUpper(hex.EncodeToString(c.SubjectKeyId))
	}
	if len(c.AuthorityKeyId) > 0 {
		cert.AuthorityKeyID = strings.ToUpper(hex.EncodeToString(c.AuthorityKeyId))
	}
	enrichFromDER(&cert, c.Raw)
	return cert
}

func subjectFromName(dn string, c *x509.Certificate) Subject {
	return Subject{
		CommonName:   c.Subject.CommonName,
		Organization: first(c.Subject.Organization),
		OrgUnit:      first(c.Subject.OrganizationalUnit),
		Country:      first(c.Subject.Country),
		Locality:     first(c.Subject.Locality),
		State:        first(c.Subject.Province),
		DN:           dn,
	}
}

func issuerFromCert(c *x509.Certificate) Subject {
	return Subject{
		CommonName:   c.Issuer.CommonName,
		Organization: first(c.Issuer.Organization),
		OrgUnit:      first(c.Issuer.OrganizationalUnit),
		Country:      first(c.Issuer.Country),
		Locality:     first(c.Issuer.Locality),
		State:        first(c.Issuer.Province),
		DN:           c.Issuer.String(),
	}
}

// keyUsageStrings renders the x509 key-usage bitmask as the same tokens Kalkan
// emits, so the full list is consistent across leaf and CA nodes.
func keyUsageStrings(ku x509.KeyUsage) []string {
	var out []string
	for _, m := range []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "nonRepudiation"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
	} {
		if ku&m.bit != 0 {
			out = append(out, m.name)
		}
	}
	return out
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
