package core

import (
	"crypto/x509"
	"os"
	"regexp"

	"golang.org/x/crypto/ocsp"
)

// reasonNames maps X.509 CRL reason codes (shared by OCSP) to text.
var reasonNames = map[int]string{
	0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL",
	9: "privilegeWithdrawn", 10: "aACompromise",
}

func reasonName(code int) string {
	if n, ok := reasonNames[code]; ok {
		return n
	}
	return ""
}

// ocspReasonRe pulls a "Reason: <word>" out of Kalkan's outInfo text, the
// fallback for GOST responses that the structured parser cannot verify.
var ocspReasonRe = regexp.MustCompile(`(?i)reason:\s*([A-Za-z]+)`)

// enrichFromOCSP fills the structured OCSP fields (thisUpdate/nextUpdate/
// producedAt/revocationTime/reason). It first tries a structured parse; for
// responses it cannot parse (e.g. GOST) it falls back to Kalkan's info text for
// the reason. Best-effort — leaves fields unset on failure.
func enrichFromOCSP(status *RevocationStatus, respDER []byte, info string) {
	if len(respDER) > 0 {
		// nil issuer: parse structurally without verifying the signature (Kalkan
		// already produced the trusted verdict).
		if r, err := ocsp.ParseResponse(respDER, nil); err == nil {
			tu := r.ThisUpdate.UTC()
			status.ThisUpdate = &tu
			if !r.NextUpdate.IsZero() {
				nu := r.NextUpdate.UTC()
				status.NextUpdate = &nu
			}
			if !r.ProducedAt.IsZero() {
				pa := r.ProducedAt.UTC()
				status.ProducedAt = &pa
			}
			if r.Status == ocsp.Revoked {
				status.Revoked = true
				if !r.RevokedAt.IsZero() {
					ra := r.RevokedAt.UTC()
					status.RevocationTime = &ra
				}
				if n := reasonName(r.RevocationReason); n != "" {
					status.Reason = n
				}
			}
			return
		}
	}
	if status.Reason == "" {
		if m := ocspReasonRe.FindStringSubmatch(info); m != nil {
			status.Reason = m[1]
		}
	}
}

// enrichFromCRL fills revocation fields from a CRL (DER/PEM): validity window and
// the target certificate's entry if present. Signature is not verified here
// (Kalkan does that, incl. GOST); parsing is structural.
func enrichFromCRL(status *RevocationStatus, crl, certDER []byte) {
	rl, err := x509.ParseRevocationList(toDER(crl, EncodingPEM))
	if err != nil || rl == nil {
		return
	}
	if !rl.ThisUpdate.IsZero() {
		tu := rl.ThisUpdate.UTC()
		status.ThisUpdate = &tu
	}
	if !rl.NextUpdate.IsZero() {
		nu := rl.NextUpdate.UTC()
		status.NextUpdate = &nu
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil || cert == nil {
		return
	}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber == nil || cert.SerialNumber == nil {
			continue
		}
		if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			status.Revoked = true
			rt := e.RevocationTime.UTC()
			status.RevocationTime = &rt
			if n := reasonName(e.ReasonCode); n != "" {
				status.Reason = n
			}
			return
		}
	}
}

// writeTempCRL writes CRL bytes to a private temp file for Kalkan (which reads a
// path), returning the path and a cleanup func.
func writeTempCRL(crl []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "kalkan-crl-*.crl")
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	if _, err := f.Write(crl); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}
