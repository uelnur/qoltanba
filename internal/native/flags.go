package native

// Native KalkanCrypt.h constants. They live here, in the driver, and nowhere
// else: the domain and transports work with provider abstractions, not Kalkan
// hex values. A library version/variant change is patched only in this layer.

// Key storage kinds (KC_LoadKeyStore, storage).
const (
	kcstPKCS12     = 0x00000001
	kcstKZIDCard   = 0x00000002
	kcstKaztoken   = 0x00000004
	kcstEToken72K  = 0x00000008
	kcstJaCarta    = 0x00000010
	kcstX509Cert   = 0x00000020
	kcstAKey       = 0x00000040
	kcstEToken5110 = 0x00000080
)

// Certificate format (X509ExportCertificateFromStore / X509CertificateGetInfo input).
const (
	kcCertDER = 0x00000101
	kcCertPEM = 0x00000102
	kcCertB64 = 0x00000104
)

// Loaded CA kind (X509LoadCertificateFromFile, certType).
const (
	kcCertCA           = 0x00000201
	kcCertIntermediate = 0x00000202
	kcCertUser         = 0x00000204
)

// Validation kind (X509ValidateCertificate, validType).
const (
	kcUseNothing = 0x00000401
	kcUseCRL     = 0x00000402
	kcUseOCSP    = 0x00000404
)

// Operation flags (SignData/VerifyData/SignXML/…).
const (
	kcSignDraft       = 0x00000001
	kcSignCMS         = 0x00000002
	kcInPEM           = 0x00000004
	kcInDER           = 0x00000008
	kcInBase64        = 0x00000010
	kcDetachedData    = 0x00000040
	kcWithCert        = 0x00000080
	kcWithTimestamp   = 0x00000100
	kcOutPEM          = 0x00000200
	kcOutDER          = 0x00000400
	kcOutBase64       = 0x00000800
	kcInFile          = 0x00008000
	kcNoCheckCertTime = 0x00010000
	kcHashSHA256      = 0x00020000
	kcHashGOST95      = 0x00040000
	kcGetOCSPResponse = 0x00080000
)

// Proxy flags for KC_SetProxy (library-internal HTTP: OCSP/AIA/TSA/CA download).
const (
	kcProxyOff  = 0x00001000
	kcProxyOn   = 0x00002000
	kcProxyAuth = 0x00004000
)

// Certificate property ids and names (X509CertificateGetInfo, propId). The order
// is fixed — this is the exhaustive list from KalkanCrypt.h.
type certProp struct {
	id   int
	name string
}

var certProps = []certProp{
	{0x00000801, "ISSUER_COUNTRYNAME"},
	{0x00000802, "ISSUER_SOPN"},
	{0x00000803, "ISSUER_LOCALITYNAME"},
	{0x00000804, "ISSUER_ORG_NAME"},
	{0x00000805, "ISSUER_ORGUNIT_NAME"},
	{0x00000806, "ISSUER_COMMONNAME"},
	{0x00000807, "SUBJECT_COUNTRYNAME"},
	{0x00000808, "SUBJECT_SOPN"},
	{0x00000809, "SUBJECT_LOCALITYNAME"},
	{0x0000080a, "SUBJECT_COMMONNAME"},
	{0x0000080b, "SUBJECT_GIVENNAME"},
	{0x0000080c, "SUBJECT_SURNAME"},
	{0x0000080d, "SUBJECT_SERIALNUMBER"},
	{0x0000080e, "SUBJECT_EMAIL"},
	{0x0000080f, "SUBJECT_ORG_NAME"},
	{0x00000810, "SUBJECT_ORGUNIT_NAME"},
	{0x00000811, "SUBJECT_BC"},
	{0x00000812, "SUBJECT_DC"},
	{0x00000813, "NOTBEFORE"},
	{0x00000814, "NOTAFTER"},
	{0x00000815, "KEY_USAGE"},
	{0x00000816, "EXT_KEY_USAGE"},
	{0x00000817, "AUTH_KEY_ID"},
	{0x00000818, "SUBJ_KEY_ID"},
	{0x00000819, "CERT_SN"},
	{0x0000081a, "ISSUER_DN"},
	{0x0000081b, "SUBJECT_DN"},
	{0x0000081c, "SIGNATURE_ALG"},
	{0x0000081d, "PUBKEY"},
	{0x0000081e, "POLICIES_ID"},
}
