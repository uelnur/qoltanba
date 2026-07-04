package provider

import (
	"errors"
	"fmt"
)

// Explanation is a human-facing rendering of a provider error: a stable Key, a
// plain-language Message and a suggested Action, plus the raw KCR_* Code when the
// error carries one. It turns "0x08F0000B" into "the certificate has expired —
// reissue it or use a valid one", so a caller without a crypto background can act
// on the failure directly.
//
// Key is a stable, locale-independent identifier (e.g. "cert.expired"). Message
// and Action are English today; the Key is the seam for localization — a future
// locale table maps Key+locale to translated text without touching call sites or
// the wire contract. Keep Key stable across releases; it is part of the contract.
type Explanation struct {
	Code    string // raw KCR_* code, e.g. "0x08F0000B"; empty if the error has none
	Key     string // stable message identifier, e.g. "cert.expired"
	Message string // what went wrong, in plain language
	Action  string // what the caller can do about it
}

// catalogEntry binds a typed sentinel to its friendly rendering.
type catalogEntry struct {
	sentinel error
	key      string
	message  string
	action   string
}

// catalog maps every recognized sentinel to a friendly Key/Message/Action. It is
// ordered (not a map) so Explain resolves deterministically: an error unwraps to
// exactly one sentinel, but iterating a fixed slice keeps behavior stable and
// makes the most-specific entries easy to place first if that ever matters.
//
// Every sentinel in errors.go should have an entry here; unmatched errors fall
// back to genericEntry. To localize, translate message/action per Key — do not
// rename keys.
var catalog = []catalogEntry{
	{ErrInvalidPassword, "container.password.invalid",
		"The private-key container password is incorrect.",
		"Check the password for the key container (PKCS#12/PFX) and try again."},
	{ErrKeyNotFound, "key.not_found",
		"No private key was found in the container.",
		"Verify the container holds a signing key and that the right alias is selected."},
	{ErrCertNotFound, "cert.not_found",
		"The certificate was not found.",
		"Provide the signer certificate, or check that the key container includes it."},
	{ErrCertExpired, "cert.expired",
		"The certificate is outside its validity period.",
		"Reissue the certificate, or use one that is currently valid."},
	{ErrCertTimeInvalid, "cert.time_invalid",
		"The certificate is not valid at the requested time.",
		"Use a certificate valid at the signing/verification time, or adjust the check time."},
	{ErrCertParse, "cert.parse_error",
		"The certificate could not be parsed.",
		"Check the encoding (PEM/DER/Base64) and that the bytes are a valid X.509 certificate."},
	{ErrSignFormatMismatch, "sign.format_mismatch",
		"The signature format flag does not match the data.",
		"Ensure the format (CMS/XML/WSSE) and the detached flag match how the data was signed."},
	{ErrSignatureInvalid, "signature.invalid",
		"The signature is cryptographically invalid.",
		"The data was altered or signed with a different key — re-sign, or verify against the original source."},
	{ErrNoSignature, "signature.absent",
		"No signature was found in the input.",
		"Provide a signed container, and check that the format flag matches it."},
	{ErrChainInvalid, "chain.invalid",
		"The certificate chain could not be built or verified.",
		"Supply the issuing CA certificates (trust store) needed to complete the chain."},
	{ErrCARequired, "ca.required",
		"A trusted CA certificate is required but was not available.",
		"Load the NUC CA certificates into the trust store."},
	{ErrOCSPRequest, "ocsp.request_failed",
		"The OCSP revocation check failed.",
		"Check network access to the OCSP responder, or retry later."},
	{ErrXMLParse, "xml.parse_error",
		"The XML document could not be parsed.",
		"Ensure the input is well-formed XML."},
	{ErrCMSFormat, "cms.format_unknown",
		"The CMS/PKCS#7 container format was not recognized.",
		"Check that the input is a valid CMS/PKCS#7 structure and matches the detached flag."},
	{ErrInvalidParam, "request.invalid_parameter",
		"The library rejected a request parameter.",
		"Check the operation flags and the input encoding."},
	{ErrBufferTooSmall, "buffer.too_small",
		"The library output buffer was too small.",
		"Retry the operation; if it persists, report the input size to the maintainers."},
	{ErrUnsupported, "operation.unsupported",
		"The loaded library version does not support this operation.",
		"Upgrade the Kalkan library, or use a supported operation."},
	{ErrNotReady, "service.not_ready",
		"The service is not ready — the native library is not initialized.",
		"Wait for readiness (/readyz), or check the native library configuration."},
	{ErrClosed, "service.closed",
		"The provider has been closed.",
		"Restart the service."},
}

// genericEntry is the fallback when no sentinel matches — an unrecognized KCR_*
// code with a bare NativeError. The Code (and Text, via the caller) still carry
// the raw detail for diagnosis.
var genericEntry = catalogEntry{
	key:     "library.error",
	message: "The cryptographic library returned an error.",
	action:  "Inspect the code and text detail; consult the error catalog or the maintainers.",
}

// Explain renders err into a human-facing Explanation. It fills Code from a
// NativeError when present, then matches the error against the catalog by
// sentinel (errors.Is), falling back to genericEntry. Returns the zero value for
// a nil error.
func Explain(err error) Explanation {
	if err == nil {
		return Explanation{}
	}
	exp := Explanation{}
	var ne *NativeError
	if errors.As(err, &ne) && ne.Code != 0 {
		exp.Code = fmt.Sprintf("0x%08X", ne.Code)
	}
	for _, e := range catalog {
		if errors.Is(err, e.sentinel) {
			exp.Key, exp.Message, exp.Action = e.key, e.message, e.action
			return exp
		}
	}
	exp.Key, exp.Message, exp.Action = genericEntry.key, genericEntry.message, genericEntry.action
	return exp
}
