package core

import "github.com/uelnur/qoltanba/internal/pki"

// AlgorithmGeneration classifies the cryptographic generation a certificate
// belongs to. RK is mid-transition between GOST generations (and away from the
// RSA/SHA-1 profiles), so "which algorithm" is not enough for a consumer to act
// on — they need to know whether it is the current one, and what to do if not.
type AlgorithmGeneration string

const (
	// GenerationCurrent is what the NUC issues today: GOST 34.10-2015.
	GenerationCurrent AlgorithmGeneration = "current"
	// GenerationLegacy is a superseded profile that still verifies: the older
	// GOST 34.310/34.311 branch, or an RSA profile. Signatures made with it stay
	// verifiable — the transition is about issuing new certificates, not about
	// rejecting old signatures.
	GenerationLegacy AlgorithmGeneration = "legacy"
	// GenerationWeak is a profile whose digest is no longer considered sound
	// (SHA-1). It still verifies, but it should not be relied on for new
	// signatures.
	GenerationWeak AlgorithmGeneration = "weak"
	// GenerationUnknown means the algorithm could not be determined.
	GenerationUnknown AlgorithmGeneration = "unknown"
)

// AlgorithmInfo describes a signer's algorithm and what, if anything, the holder
// should do about it. Advice is empty for the current generation: a consumer
// should not be nagged about a certificate that is exactly right.
type AlgorithmInfo struct {
	KeyAlgorithm string              `json:"keyAlgorithm,omitempty"` // rsa | gost2004 | gost2015-256/512
	SignatureOID string              `json:"signatureOid,omitempty"`
	Generation   AlgorithmGeneration `json:"generation"`
	Advice       string              `json:"advice,omitempty"`
}

// algorithmInfo classifies a certificate's algorithm. The classification keys off
// the derived key family rather than the raw OID, so a new OID in the same family
// lands in the right bucket without a second table to keep in sync.
func algorithmInfo(cert Certificate) AlgorithmInfo {
	info := AlgorithmInfo{
		KeyAlgorithm: cert.KeyAlgorithm,
		SignatureOID: cert.SignatureAlgorithmOID,
		Generation:   GenerationUnknown,
	}
	switch cert.KeyAlgorithm {
	case "gost2015-256", "gost2015-512":
		info.Generation = GenerationCurrent
	case "gost2004":
		info.Generation = GenerationLegacy
		info.Advice = "This certificate uses the superseded GOST 34.310/34.311 profile. " +
			"Existing signatures stay verifiable; reissue the certificate under GOST 34.10-2015 for new ones."
	case "rsa":
		// The RSA profiles differ in how much they are worth trusting: SHA-1 is
		// broken for collision resistance, SHA-256 is merely not the RK default.
		if cert.SignatureAlgorithmOID == pki.SignSHA1RSA {
			info.Generation = GenerationWeak
			info.Advice = "This certificate is signed with SHA-1, which is no longer collision-resistant. " +
				"Reissue it under GOST 34.10-2015 before signing anything new."
		} else {
			info.Generation = GenerationLegacy
			info.Advice = "This certificate uses an RSA profile rather than the GOST 34.10-2015 one the NUC issues today. " +
				"Existing signatures stay verifiable; reissue for new ones."
		}
	case "":
		info.Advice = "The signature algorithm could not be determined from the certificate."
	}
	return info
}
