// Package trust implements the core.TrustStore port: the CA certificates used to
// anchor and build chains during verification and validation. It is
// infrastructure backing a domain-declared interface.
//
// Scope (synchronous core): load CA certificates from a directory of PEM files.
// A self-signed certificate is treated as a root anchor, others as
// intermediates. The RK CA catalog (internal/pki) lists official CAs by URL;
// fetching/pinning them is a later concern — here the operator supplies the
// actual certificate bytes.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/uelnur/qoltanba/internal/core"
)

// Store holds the loaded trust anchors.
type Store struct {
	anchors []core.TrustedCert
}

// Empty returns a trust store with no anchors (valid for CMS verification, which
// does not require them).
func Empty() *Store { return &Store{} }

// Anchors implements core.TrustStore.
func (s *Store) Anchors() []core.TrustedCert { return s.anchors }

// LoadDir builds a Store from every PEM/CRT file under dir (non-recursive). Each
// certificate is classified root vs intermediate by whether it is self-signed.
// An empty dir yields an empty store without error.
func LoadDir(dir string) (*Store, error) {
	if dir == "" {
		return Empty(), nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Empty(), nil
		}
		return nil, fmt.Errorf("trust: read dir %s: %w", dir, err)
	}
	s := &Store{}
	for _, e := range entries {
		if e.IsDir() || !isCertFile(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("trust: read %s: %w", e.Name(), err)
		}
		s.addPEM(raw)
	}
	return s, nil
}

// addPEM appends every certificate block found in raw.
func (s *Store) addPEM(raw []byte) {
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		s.anchors = append(s.anchors, core.TrustedCert{
			Cert:         pem.EncodeToMemory(block),
			Intermediate: !isSelfSigned(block.Bytes),
		})
	}
}

// addDER appends one certificate given as raw DER, classifying it root vs
// intermediate. It reports whether the DER parsed as a certificate.
func (s *Store) addDER(der []byte) bool {
	if _, err := x509.ParseCertificate(der); err != nil {
		return false
	}
	s.anchors = append(s.anchors, core.TrustedCert{
		Cert:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Intermediate: !isSelfSigned(der),
	})
	return true
}

// isSelfSigned reports whether the DER certificate is self-issued (issuer ==
// subject), the classification heuristic for a root anchor. A parse failure
// defaults to intermediate — the safer classification.
func isSelfSigned(der []byte) bool {
	c, err := x509.ParseCertificate(der)
	if err != nil || c == nil {
		return false
	}
	return bytes.Equal(c.RawIssuer, c.RawSubject)
}

func isCertFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".crt", ".cer":
		return true
	default:
		return false
	}
}
