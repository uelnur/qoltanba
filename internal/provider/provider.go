// Package provider declares the port between the domain layer and the driver
// of the native Kalkan library (ports & adapters).
//
// This is the single contract through which the domain reaches cryptography.
// The package deliberately contains no cgo, no C types and no KCR_* codes: the
// driver (internal/native) implements Provider and maps native details into
// these Go-friendly structs and typed errors. The domain depends on the
// interface, not the implementation, so it can be tested with a fake and no
// library present.
//
// Ownership: in the target architecture the domain declares this port. Until
// the domain layer exists, the contract lives here as a shared package and can
// move later without touching the driver.
package provider

import "context"

// Provider is a concurrency-safe facade over Kalkan. The implementation (a
// pool) spreads calls across isolated library instances; callers never need to
// serialize. The operation set mirrors what the C-API actually exposes; new
// methods are added as the driver grows without changing existing signatures.
type Provider interface {
	// Capabilities reports which operations the loaded library version exposes.
	// The Kalkan function table grows between versions, so some methods may be
	// absent. Check before calling an optional operation; an unavailable one
	// returns ErrUnsupported.
	Capabilities() Capabilities

	// SignCMS signs data as CMS/PKCS#7. The key comes from req.Key and is loaded
	// for the duration of the call. Supports detached and co-sign
	// (req.ExistingSignature).
	SignCMS(ctx context.Context, req SignRequest) (SignResult, error)

	// VerifyCMS verifies a CMS signature and extracts everything available:
	// validity, signer certificate(s), recovered content, timestamp.
	VerifyCMS(ctx context.Context, req VerifyRequest) (VerifyResult, error)

	// SignXML signs XML (XMLDSig) with the key from req.Key.
	SignXML(ctx context.Context, req SignXMLRequest) (SignResult, error)

	// VerifyXML verifies an XML signature and extracts the signer(s).
	VerifyXML(ctx context.Context, req VerifyRequest) (VerifyResult, error)

	// SignWSSE signs a SOAP envelope with WS-Security; verify it via VerifyXML.
	SignWSSE(ctx context.Context, req SignWSSERequest) (SignResult, error)

	// ExportOwnerCert opens a key container and exports the owner certificate
	// (a pkcs12/info-style operation) together with the store alias.
	ExportOwnerCert(ctx context.Context, key KeyRef, format CertFormat) (ExportResult, error)

	// Hash computes a digest of the data (for streaming signatures and JWT).
	Hash(ctx context.Context, req HashRequest) (HashResult, error)

	// SignHash signs a precomputed digest with the key from req.Key.
	SignHash(ctx context.Context, req SignHashRequest) (SignResult, error)

	// CertProperties extracts every certificate property (X509CertificateGetInfo
	// for each propId). It returns a flat field set; derivation
	// (IIN/BIN/role/gender) is the domain's job.
	CertProperties(ctx context.Context, cert []byte, format CertFormat) (CertProperties, error)

	// ValidateCert checks certificate status via OCSP or CRL and establishes
	// chain trust.
	ValidateCert(ctx context.Context, req ValidateRequest) (ValidateResult, error)

	// Close releases every library instance in the pool. After Close any call
	// returns ErrClosed.
	Close() error
}
