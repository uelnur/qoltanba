package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// ReceiptSigner signs the service's own statements. It is the same RS256
// mechanism that issues OIDC id_tokens, declared here as a port so the domain
// does not depend on that package: any implementation whose public key the
// consumer can fetch (JWKS) will do.
type ReceiptSigner interface {
	// Sign returns a compact JWS over the JSON-encoded claims.
	Sign(claims any) (string, error)
	// KeyID is the JWKS key id the consumer verifies against.
	KeyID() string
}

// receiptType marks the payload kind, so a consumer that also handles id_tokens
// cannot confuse the two.
const receiptType = "qoltanba.verification-receipt.v1"

// ReceiptClaims is the payload of a verification receipt: the service's own
// machine-checkable statement that it performed this verification and reached
// this verdict. It is deliberately not a certificate of the signature's validity
// forever — it attests to a check made at a point in time, by this service, over
// exactly these bytes (the report carries their digests).
//
// The consumer stores it and can later prove what was checked without re-running
// the verification, verifying it against the service's published JWKS.
type ReceiptClaims struct {
	Type     string              `json:"typ"`
	Issuer   string              `json:"iss,omitempty"`
	IssuedAt int64               `json:"iat"`
	ID       string              `json:"jti"`
	Verdict  ReportVerdict       `json:"verdict"`
	Report   *VerificationReport `json:"report"`
}

// issueReceipt signs the report. It returns an empty string when no signer is
// configured, so the flag degrades to "no receipt" rather than failing the
// verification the caller actually asked for.
func (s *Service) issueReceipt(report *VerificationReport, now time.Time) (string, error) {
	if s.receiptSigner == nil || report == nil {
		return "", nil
	}
	id, err := receiptID()
	if err != nil {
		return "", err
	}
	token, err := s.receiptSigner.Sign(ReceiptClaims{
		Type:     receiptType,
		Issuer:   s.receiptIssuer,
		IssuedAt: now.Unix(),
		ID:       id,
		Verdict:  report.Verdict,
		Report:   report,
	})
	if err != nil {
		return "", fmt.Errorf("sign receipt: %w", err)
	}
	return token, nil
}

// receiptID is a unique identifier for one receipt, so duplicates are detectable
// in an audit log.
func receiptID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("receipt id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
