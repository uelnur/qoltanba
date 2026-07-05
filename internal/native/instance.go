package native

/*
#cgo !windows LDFLAGS: -ldl
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"bytes"
	"fmt"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/uelnur/qoltanba/internal/provider"
)

// instance is one loaded, initialized Kalkan library instance. It is not safe
// for concurrent use: it belongs to a single worker that serializes access and
// keeps it pinned to one OS thread. This type only maps C to Go and applies the
// length-then-data convention; it holds no orchestration.
type instance struct {
	c        *C.KcInstance
	id       int
	isolated bool // loaded into a private namespace (isolation achieved)
}

// openInstance is the single load/isolation seam. Change the concurrency model
// (dlmopen namespace vs shared dlopen) here and nowhere else.
//
// In isolated mode wrapperPath must be a wrapper whose dependencies are baked
// into DT_NEEDED (Open prepares it with patchelf). When isolation fails,
// in.isolated becomes false.
func openInstance(id int, wrapperPath string, isolated bool) (*instance, error) {
	cWrap := C.CString(wrapperPath)
	defer C.free(unsafe.Pointer(cWrap))

	iso := C.int(0)
	if isolated {
		iso = 1
	}
	var fallback C.int
	errBuf := C.malloc(4096)
	defer C.free(errBuf)
	errLen := C.int(4096)

	c := C.kc_open(cWrap, iso, &fallback, (*C.char)(errBuf), &errLen)
	if c == nil {
		msg := C.GoStringN((*C.char)(errBuf), errLen)
		return nil, fmt.Errorf("kalkan: load instance %d: %s", id, msg)
	}
	in := &instance{c: c, id: id, isolated: isolated && fallback == 0}
	if rc := uint32(C.kc_init(in.c)); rc != kcrOK {
		detail := in.lastErr()
		in.close()
		return nil, nativeErr("KC_Init", rc, detail)
	}
	return in, nil
}

func (in *instance) close() {
	if in != nil && in.c != nil {
		iso := C.int(0)
		if in.isolated {
			iso = 1
		}
		C.kc_close(in.c, iso)
		in.c = nil
	}
}

func (in *instance) has(capID int) bool { return C.kc_has(in.c, C.int(capID)) != 0 }

func (in *instance) isIsolated() bool { return in.isolated }

func (in *instance) lastErr() string {
	buf := C.malloc(1 << 16)
	defer C.free(buf)
	l := C.int(1 << 16)
	C.kc_lasterr(in.c, (*C.char)(buf), &l)
	if l <= 0 {
		return ""
	}
	return string(trimNul(C.GoBytes(buf, l)))
}

// withBuf runs a call using Kalkan's length-then-data convention: it allocates a
// buffer, passes its capacity, and on KCR_BUFFER_TOO_SMALL doubles and retries.
// It returns the written bytes (only on rc==0 with a valid length) and the raw
// code.
func withBuf(initCap int, fn func(buf unsafe.Pointer, outLen *C.int) C.ulong) ([]byte, uint32) {
	capN := initCap
	const maxCap = 1 << 25
	for {
		buf := C.malloc(C.size_t(capN))
		outLen := C.int(capN)
		rc := uint32(fn(buf, &outLen))
		if rc == kcrBufferTooSmall && capN < maxCap {
			C.free(buf)
			capN *= 2
			continue
		}
		var out []byte
		// Read the output only on success with 0<outLen<=cap; otherwise the
		// buffer may hold garbage.
		if rc == kcrOK && outLen > 0 && int(outLen) <= capN {
			out = C.GoBytes(buf, outLen)
		}
		C.free(buf)
		return out, rc
	}
}

func (in *instance) loadKey(ref provider.KeyRef) (string, error) {
	cPass := C.CString(ref.Password)
	defer C.free(unsafe.Pointer(cPass))
	cCont := C.CString(ref.Path)
	defer C.free(unsafe.Pointer(cCont))
	aliasBuf := C.malloc(4096)
	defer C.free(aliasBuf)
	rc := uint32(C.kc_loadkey(in.c, C.int(storageFlag(ref.Storage)),
		cPass, C.int(len(ref.Password)), cCont, C.int(len(ref.Path)),
		(*C.char)(aliasBuf), 4096))
	if rc != kcrOK {
		return "", nativeErr("LoadKeyStore", rc, in.lastErr())
	}
	return C.GoString((*C.char)(aliasBuf)), nil
}

func (in *instance) exportCert(alias string, format int) ([]byte, error) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	out, rc := withBuf(1<<18, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_export_cert(in.c, cAlias, C.int(format), (*C.char)(buf), outLen)
	})
	if rc != kcrOK {
		return nil, nativeErr("ExportCertificate", rc, in.lastErr())
	}
	return trimNul(out), nil
}

// certInfo extracts all certificate properties. A missing property
// (KCR_GETCERTPROPERR) is normal: the field is marked OK=false, not an error.
// afterEq strips the "name=" prefix that X509CertificateGetInfo prepends to most
// single-valued property renderings (e.g. "notBefore=08.05.2026 06:45:13 +00:00"
// -> "08.05.2026 06:45:13 +00:00", "C=KZ" -> "KZ"). The prefix is an identifier
// immediately followed by '='. Values that don't fit that shape are returned
// unchanged, which is exactly what the exceptions need: the DN aggregates render
// with spaces ("CN = ..., C = KZ") so the first '=' is not identifier-adjacent,
// and the base64 public key has non-identifier bytes before its '=' padding.
func afterEq(v string) string {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '=' {
			if i == 0 {
				return v // nothing before '=' — not a prefix
			}
			return v[i+1:]
		}
		isIdent := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.'
		if !isIdent {
			return v // non-identifier byte before any '=' — leave untouched
		}
	}
	return v
}

func (in *instance) certInfo(cert []byte) provider.CertProperties {
	cCert := C.CBytes(cert)
	defer C.free(cCert)
	props := provider.CertProperties{Fields: make([]provider.CertField, 0, len(certProps))}
	for _, p := range certProps {
		out, rc := withBuf(1<<16, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
			return C.kc_cert_info(in.c, (*C.char)(cCert), C.int(len(cert)),
				C.int(p.id), (*C.uchar)(buf), outLen)
		})
		f := provider.CertField{ID: uint32(p.id), Name: p.name}
		if rc == kcrOK && len(out) > 0 {
			b := trimNul(out)
			f.OK = true
			if utf8.Valid(b) && isPrintable(b) {
				f.Value = afterEq(string(b))
			} else {
				f.Raw = b
			}
		}
		props.Fields = append(props.Fields, f)
	}
	return props
}

func (in *instance) signData(alias string, flags int, data, inSign []byte) ([]byte, error) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	cData := C.CBytes(data)
	defer C.free(cData)
	var cSign unsafe.Pointer
	var signLen C.int
	if len(inSign) > 0 {
		cSign = C.CBytes(inSign)
		defer C.free(cSign)
		signLen = C.int(len(inSign))
	}
	out, rc := withBuf(1<<20, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_sign_data(in.c, cAlias, C.int(flags), (*C.char)(cData), C.int(len(data)),
			(*C.uchar)(cSign), signLen, (*C.uchar)(buf), outLen)
	})
	if rc != kcrOK {
		return nil, nativeErr("SignData", rc, in.lastErr())
	}
	return trimNul(out), nil
}

// verifyOut holds the raw VerifyData result: code and three output buffers.
type verifyOut struct {
	code   uint32
	data   []byte // recovered/verified content
	verify []byte // outVerifyInfo
	cert   []byte // signer certificate
}

func (in *instance) verifyData(alias string, flags int, data, sign []byte, inCertID int) verifyOut {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	var cData unsafe.Pointer
	var dataLen C.int
	if len(data) > 0 {
		cData = C.CBytes(data)
		defer C.free(cData)
		dataLen = C.int(len(data))
	}
	cSign := C.CBytes(sign)
	defer C.free(cSign)

	const cap = 1 << 20
	outData := C.malloc(cap)
	defer C.free(outData)
	outVer := C.malloc(cap)
	defer C.free(outVer)
	outCert := C.malloc(cap)
	defer C.free(outCert)
	dl := C.int(cap)
	vl := C.int(cap)
	cl := C.int(cap)

	rc := uint32(C.kc_verify_data(in.c, cAlias, C.int(flags),
		(*C.char)(cData), dataLen, (*C.uchar)(cSign), C.int(len(sign)),
		(*C.char)(outData), &dl, (*C.char)(outVer), &vl,
		C.int(inCertID), (*C.char)(outCert), &cl))

	res := verifyOut{code: rc}
	if vl > 0 && int(vl) < cap {
		res.verify = trimNul(C.GoBytes(outVer, vl))
	}
	if dl > 0 && int(dl) < cap {
		res.data = trimNul(C.GoBytes(outData, dl))
	}
	// Parse the certificate only on success with a valid length; otherwise the
	// library can crash on garbage (SIGSEGV).
	if rc == kcrOK && cl > 0 && int(cl) < cap {
		res.cert = trimNul(C.GoBytes(outCert, cl))
	}
	return res
}

func (in *instance) signXML(alias string, flags int, xml []byte, nodeID, parentNode, parentNS string) ([]byte, error) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	cXML := C.CBytes(xml)
	defer C.free(cXML)
	cNode := C.CString(nodeID)
	defer C.free(unsafe.Pointer(cNode))
	cParent := C.CString(parentNode)
	defer C.free(unsafe.Pointer(cParent))
	cNS := C.CString(parentNS)
	defer C.free(unsafe.Pointer(cNS))
	out, rc := withBuf(1<<20, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_sign_xml(in.c, cAlias, C.int(flags), (*C.char)(cXML), C.int(len(xml)),
			(*C.uchar)(buf), outLen, cNode, cParent, cNS)
	})
	if rc != kcrOK {
		return nil, nativeErr("SignXML", rc, in.lastErr())
	}
	return trimNul(out), nil
}

func (in *instance) signWSSE(alias string, flags int, xml []byte, nodeID string) ([]byte, error) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	cXML := C.CBytes(xml)
	defer C.free(cXML)
	cNode := C.CString(nodeID)
	defer C.free(unsafe.Pointer(cNode))
	out, rc := withBuf(1<<20, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_sign_wsse(in.c, cAlias, C.ulong(flags), (*C.char)(cXML), C.int(len(xml)),
			(*C.uchar)(buf), outLen, cNode)
	})
	if rc != kcrOK {
		return nil, nativeErr("SignWSSE", rc, in.lastErr())
	}
	return trimNul(out), nil
}

// hashData computes a digest (HashData). The output is binary, so it is not
// NUL-trimmed.
func (in *instance) hashData(algorithm string, flags int, data []byte) ([]byte, error) {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))
	cData := C.CBytes(data)
	defer C.free(cData)
	out, rc := withBuf(1<<16, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_hash_data(in.c, cAlg, C.int(flags), (*C.char)(cData), C.int(len(data)),
			(*C.uchar)(buf), outLen)
	})
	if rc != kcrOK {
		return nil, nativeErr("HashData", rc, in.lastErr())
	}
	return out, nil
}

// signHash signs a precomputed digest (SignHash). The output is returned as-is
// (may be DER/binary), so it is not NUL-trimmed.
func (in *instance) signHash(alias string, flags int, hash []byte) ([]byte, error) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	cHash := C.CBytes(hash)
	defer C.free(cHash)
	out, rc := withBuf(1<<18, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_sign_hash(in.c, cAlias, C.int(flags), (*C.char)(cHash), C.int(len(hash)),
			(*C.uchar)(buf), outLen)
	})
	if rc != kcrOK {
		return nil, nativeErr("SignHash", rc, in.lastErr())
	}
	return out, nil
}

func (in *instance) verifyXML(alias string, flags int, xml []byte) ([]byte, uint32) {
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))
	cXML := C.CBytes(xml)
	defer C.free(cXML)
	out, rc := withBuf(1<<18, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_verify_xml(in.c, cAlias, C.int(flags), (*C.char)(cXML), C.int(len(xml)),
			(*C.char)(buf), outLen)
	})
	return trimNul(out), rc
}

func (in *instance) certFromXML(xml []byte, sigID int) ([]byte, uint32) {
	cXML := C.CBytes(xml)
	defer C.free(cXML)
	out, rc := withBuf(1<<18, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_cert_from_xml(in.c, (*C.char)(cXML), C.int(len(xml)), C.int(sigID),
			(*C.char)(buf), outLen)
	})
	return trimNul(out), rc
}

func (in *instance) certFromCMS(cms []byte, sigID, flags int) ([]byte, uint32) {
	cCMS := C.CBytes(cms)
	defer C.free(cCMS)
	out, rc := withBuf(1<<18, func(buf unsafe.Pointer, outLen *C.int) C.ulong {
		return C.kc_cert_from_cms(in.c, (*C.char)(cCMS), C.int(len(cms)), C.int(sigID),
			C.int(flags), (*C.char)(buf), outLen)
	})
	return trimNul(out), rc
}

func (in *instance) timeFromSig(sig []byte, flags, sigID int) (time.Time, uint32) {
	cSig := C.CBytes(sig)
	defer C.free(cSig)
	var t C.longlong
	rc := uint32(C.kc_time_from_sig(in.c, (*C.char)(cSig), C.int(len(sig)), C.int(flags),
		C.int(sigID), &t))
	if rc == kcrOK && t > 0 {
		return time.Unix(int64(t), 0), rc
	}
	return time.Time{}, rc
}

func (in *instance) loadCertFile(path string, certType int) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	rc := uint32(C.kc_load_cert_file(in.c, cPath, C.int(certType)))
	if rc != kcrOK {
		return nativeErr("LoadCertificateFromFile", rc, in.lastErr())
	}
	return nil
}

// validateOut holds the raw X509ValidateCertificate result.
type validateOut struct {
	code uint32
	info []byte
	ocsp []byte
}

func (in *instance) validate(cert []byte, validType int, path string, checkTime int64, wantOCSP bool) validateOut {
	cCert := C.CBytes(cert)
	defer C.free(cCert)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	const cap = 1 << 16
	outInfo := C.malloc(cap)
	defer C.free(outInfo)
	getOcsp := C.malloc(cap)
	defer C.free(getOcsp)
	il := C.int(cap)
	ol := C.int(cap)
	flag := 0
	if wantOCSP {
		flag = kcGetOCSPResponse
	}
	rc := uint32(C.kc_validate(in.c, (*C.char)(cCert), C.int(len(cert)), C.int(validType),
		cPath, C.longlong(checkTime), (*C.char)(outInfo), &il, C.int(flag),
		(*C.char)(getOcsp), &ol))
	res := validateOut{code: rc}
	if il > 0 && int(il) < cap {
		res.info = trimNul(C.GoBytes(outInfo, il))
	}
	if wantOCSP && ol > 0 && int(ol) < cap {
		res.ocsp = C.GoBytes(getOcsp, ol)
	}
	return res
}

func (in *instance) tsaSetURL(url string) {
	if url == "" {
		return
	}
	cURL := C.CString(url)
	defer C.free(unsafe.Pointer(cURL))
	C.kc_tsa_seturl(in.c, cURL)
}

// setProxy configures the library's internal HTTP proxy. Returns the native
// code (0 = ok, 0xFFFFFFFF = KC_SetProxy unavailable in this library version).
func (in *instance) setProxy(flags int, addr, port, user, pass string) uint32 {
	cAddr, cPort := C.CString(addr), C.CString(port)
	cUser, cPass := C.CString(user), C.CString(pass)
	defer C.free(unsafe.Pointer(cAddr))
	defer C.free(unsafe.Pointer(cPort))
	defer C.free(unsafe.Pointer(cUser))
	defer C.free(unsafe.Pointer(cPass))
	return uint32(C.kc_set_proxy(in.c, C.int(flags), cAddr, cPort, cUser, cPass))
}

func storageFlag(s provider.StorageType) int {
	switch s {
	case provider.StoragePKCS12:
		return kcstPKCS12
	case provider.StorageKZIDCard:
		return kcstKZIDCard
	case provider.StorageKaztoken:
		return kcstKaztoken
	case provider.StorageEToken72K:
		return kcstEToken72K
	case provider.StorageJaCarta:
		return kcstJaCarta
	case provider.StorageX509Cert:
		return kcstX509Cert
	case provider.StorageAKey:
		return kcstAKey
	case provider.StorageEToken5110:
		return kcstEToken5110
	default:
		return kcstPKCS12
	}
}

// trimNul cuts a buffer at the first NUL: C strings arrive NUL-terminated in
// padded buffers.
func trimNul(b []byte) []byte {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return b[:i]
	}
	return b
}

func isPrintable(b []byte) bool {
	for _, r := range string(b) {
		if r == '�' {
			return false
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
