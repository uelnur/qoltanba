package native

import "github.com/uelnur/qoltanba/internal/provider"

// KalkanCrypt return codes (KCR_*). KCR_OK == 0; others are kcrBase + offset.
// Values come from KalkanCrypt.h.
const (
	kcrOK   = 0x00000000
	kcrBase = 0x08F00000

	kcrBufferTooSmall        = kcrBase + 0x05
	kcrCertParseError        = kcrBase + 0x06
	kcrInvalidFlag           = kcrBase + 0x07
	kcrInvalidPassword       = kcrBase + 0x09
	kcrCertWrongDate         = kcrBase + 0x0a
	kcrCertExpired           = kcrBase + 0x0b
	kcrIsNotCACert           = kcrBase + 0x0c
	kcrCheckChainError       = kcrBase + 0x0e
	kcrKeyNotFound           = kcrBase + 0x16
	kcrCertNotFound          = kcrBase + 0x1b
	kcrVerifySignError       = kcrBase + 0x1c
	kcrUnknownCMSFormat      = kcrBase + 0x1e
	kcrCACertNotFound        = kcrBase + 0x20
	kcrLoadTrustedCertsErr   = kcrBase + 0x22
	kcrNoSignFound           = kcrBase + 0x24
	kcrXMLParseError         = kcrBase + 0x26
	kcrOCSPReqErr            = kcrBase + 0x30
	kcrOCSPConnErr           = kcrBase + 0x31
	kcrGetCertPropErr        = kcrBase + 0x38 // property absent — normal, not an error
	kcrSignFormat            = kcrBase + 0x39
	kcrCertTimeInvalid       = kcrBase + 0x42
	kcrLibraryNotInitialized = kcrBase + 0x101
	kcrParamError            = kcrBase + 0x300
	kcrCertStatusOK          = kcrBase + 0x400
	kcrCertStatusRevoked     = kcrBase + 0x401
	kcrCertStatusUnknown     = kcrBase + 0x402
)

// sentinelFor maps a raw KCR_* code to a typed provider sentinel. nil means no
// dedicated sentinel (a NativeError without an Unwrap target).
func sentinelFor(code uint32) error {
	switch code {
	case kcrInvalidPassword:
		return provider.ErrInvalidPassword
	case kcrKeyNotFound:
		return provider.ErrKeyNotFound
	case kcrCertNotFound:
		return provider.ErrCertNotFound
	case kcrCertExpired, kcrCertWrongDate:
		return provider.ErrCertExpired
	case kcrCertTimeInvalid:
		return provider.ErrCertTimeInvalid
	case kcrCertParseError:
		return provider.ErrCertParse
	case kcrXMLParseError:
		return provider.ErrXMLParse
	case kcrUnknownCMSFormat:
		return provider.ErrCMSFormat
	case kcrParamError, kcrInvalidFlag:
		return provider.ErrInvalidParam
	case kcrSignFormat:
		return provider.ErrSignFormatMismatch
	case kcrVerifySignError:
		return provider.ErrSignatureInvalid
	case kcrNoSignFound:
		return provider.ErrNoSignature
	case kcrCheckChainError, kcrIsNotCACert:
		return provider.ErrChainInvalid
	case kcrCACertNotFound, kcrLoadTrustedCertsErr:
		return provider.ErrCARequired
	case kcrOCSPReqErr, kcrOCSPConnErr:
		return provider.ErrOCSPRequest
	case kcrBufferTooSmall:
		return provider.ErrBufferTooSmall
	case kcrLibraryNotInitialized:
		return provider.ErrNotReady
	default:
		return nil
	}
}

// nativeErr builds a provider.NativeError from a code and the library's last
// error text.
func nativeErr(op string, code uint32, detail string) error {
	if code == kcrOK {
		return nil
	}
	return provider.NewNativeError(op, code, detail, sentinelFor(code))
}
