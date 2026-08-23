// Probe — исследовательская утилита для проектирования контрактов qoltanba.
//
// Загружает нативную библиотеку Kalkan (BYOL, путь из LIB_PATH), открывает
// тестовый ключ (KEY_PATH/KEY_PASS), и выводит ВСЁ, что удаётся извлечь:
//   - экспортированный сертификат владельца;
//   - значение каждого свойства сертификата (все KC_CERTPROP_*), с кодом возврата;
//   - результат round-trip CMS sign -> verify: outData, outVerifyInfo,
//     извлечённый сертификат подписанта (и разбор его свойств), метку времени.
//
// Итог печатается как JSON-отчёт в stdout (человеко-читаемый лог — в stderr).
// Это НЕ часть продакшн-сервиса; цель — эмпирически выяснить модель данных
// (какие поля доступны, их формат, что нужно на входе) для §5/§6 DESIGN.md.
package main

/*
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

// --- Константы из KalkanCrypt.h ---

const (
	KCST_PKCS12 = 0x00000001

	KC_CERT_PEM = 0x00000102

	KC_SIGN_CMS        = 0x00000002
	KC_IN_PEM          = 0x00000004
	KC_OUT_PEM         = 0x00000200
	KC_DETACHED_DATA   = 0x00000040
	KC_NOCHECKCERTTIME = 0x00010000

	KC_CERT_CA           = 0x00000201
	KC_CERT_INTERMEDIATE = 0x00000202
	KC_CERT_USER         = 0x00000204

	KC_USE_CRL           = 0x00000402
	KC_USE_OCSP          = 0x00000404
	KC_GET_OCSP_RESPONSE = 0x00080000
)

type propDef struct {
	ID   int
	Name string
}

// Полный список свойств сертификата (X509CertificateGetInfo), по KalkanCrypt.h.
var certProps = []propDef{
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

// --- Модель отчёта ---

type FieldResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RC        string `json:"rc"`
	Len       int    `json:"len"`
	Text      string `json:"text,omitempty"`
	Hex       string `json:"hex,omitempty"`
	Printable bool   `json:"printable"`
}

type CertDump struct {
	Label  string        `json:"label"`
	Fields []FieldResult `json:"fields"`
}

type ValidationResult struct {
	Type    string `json:"type"`
	RC      string `json:"rc"`
	Info    string `json:"info,omitempty"`
	OCSPB64 string `json:"ocspResponseB64,omitempty"`
}

type Report struct {
	LibPath          string        `json:"libPath"`
	KeyPath          string        `json:"keyPath"`
	InitRC           string        `json:"initRC"`
	LoadKeyRC        string        `json:"loadKeyRC"`
	Alias            string        `json:"alias"`
	ExportCertRC     string        `json:"exportCertRC"`
	OwnerCertPEM     string        `json:"ownerCertPEM,omitempty"`
	OwnerFields      []FieldResult `json:"ownerCertFields"`
	SignRC           string        `json:"signRC"`
	SignedCMSPEM     string        `json:"signedCmsPem,omitempty"`
	VerifyRC         string        `json:"verifyRC"`
	VerifyInfo       string        `json:"verifyInfo,omitempty"`
	VerifiedData     string        `json:"verifiedData,omitempty"`
	RecoverContentRC string        `json:"recoverContentRC,omitempty"`
	RecoveredContent string        `json:"recoveredContent,omitempty"`
	SignerFields     []FieldResult `json:"signerCertFields"`
	TimeFromSigRC    string        `json:"timeFromSigRC"`
	TimeFromSig      string        `json:"timeFromSig,omitempty"`

	// Расширение: цепочка, валидация, CMS/XML
	Chain           []CertDump         `json:"chain,omitempty"`
	ChainOrder      []string           `json:"chainOrder,omitempty"`
	AIAChain        []CertDump         `json:"aiaChain,omitempty"`
	AIAUrls         []string           `json:"aiaUrls,omitempty"`
	Validations     []ValidationResult `json:"validations,omitempty"`
	CmsSignerCertRC string             `json:"cmsGetCertRC,omitempty"`
	CmsSignerFields []FieldResult      `json:"cmsSignerFields,omitempty"`
	XmlSignRC       string             `json:"xmlSignRC,omitempty"`
	XmlVerifyRC     string             `json:"xmlVerifyRC,omitempty"`
	XmlVerifyInfo   string             `json:"xmlVerifyInfo,omitempty"`
	XmlSigAlgRC     string             `json:"xmlSigAlgRC,omitempty"`
	XmlSigAlg       string             `json:"xmlSigAlg,omitempty"`
	XmlCertRC       string             `json:"xmlGetCertRC,omitempty"`
	XmlSignerFields []FieldResult      `json:"xmlSignerFields,omitempty"`

	// Множественная подпись (co-signing) двумя разными людьми
	MultiCmsSignRC     string     `json:"multiCmsSignRC,omitempty"`
	MultiCmsVerifyRC   string     `json:"multiCmsVerifyRC,omitempty"`
	MultiCmsVerifyInfo string     `json:"multiCmsVerifyInfo,omitempty"`
	MultiCmsSigners    []CertDump `json:"multiCmsSigners,omitempty"`
	MultiXmlSignRC     string     `json:"multiXmlSignRC,omitempty"`
	MultiXmlVerifyRC   string     `json:"multiXmlVerifyRC,omitempty"`
	MultiXmlVerifyInfo string     `json:"multiXmlVerifyInfo,omitempty"`
	MultiXmlSigners    []CertDump `json:"multiXmlSigners,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

func hexS(rc C.ulong) string { return fmt.Sprintf("0x%08X", uint32(rc)) }

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// certInfo вызывает X509CertificateGetInfo и раскладывает результат по-полево.
func certInfo(cert []byte) []FieldResult {
	out := make([]FieldResult, 0, len(certProps))
	const cap = 1 << 16
	buf := C.malloc(cap)
	defer C.free(buf)
	cCert := C.CBytes(cert)
	defer C.free(cCert)

	for _, p := range certProps {
		outLen := C.int(cap)
		rc := C.probe_cert_info((*C.char)(cCert), C.int(len(cert)), C.int(p.ID),
			(*C.uchar)(buf), &outLen)
		fr := FieldResult{ID: fmt.Sprintf("0x%08X", p.ID), Name: p.Name, RC: hexS(rc)}
		if rc == 0 && outLen > 0 {
			b := C.GoBytes(buf, outLen)
			b = trimNul(b) // C-API возвращает NUL-терминированные/NUL-дополненные строки
			fr.Len = len(b)
			if utf8.Valid(b) && isPrintable(b) {
				fr.Text = string(b)
				fr.Printable = true
			} else {
				fr.Hex = fmt.Sprintf("%x", b)
			}
		}
		out = append(out, fr)
		logf("  %-22s %s len=%d %s", p.Name, fr.RC, fr.Len, truncate(fr.Text, 80))
	}
	return out
}

// trimNul обрезает строку по первому NUL (C-строка): C-API возвращает
// NUL-терминированные значения в фиксированных/дополненных буферах.
func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
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

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// aiaURLRe находит в DER-байтах сертификата URL, оканчивающийся на .cer — это
// ссылка AIA "CA Issuers" на сертификат издателя.
var aiaURLRe = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+\.cer`)

func caIssuerURL(der []byte) string {
	if m := aiaURLRe.Find(der); m != nil {
		return string(m)
	}
	return ""
}

func toDER(cert []byte) []byte {
	if blk, _ := pem.Decode(cert); blk != nil {
		return blk.Bytes
	}
	return cert
}

func toPEM(cert []byte) []byte {
	if bytes.HasPrefix(cert, []byte("-----BEGIN")) {
		return cert
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
}

func httpGetCert(url string) ([]byte, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// aiaWalk достраивает цепочку по AIA: из листа берёт URL издателя, скачивает его
// сертификат, разбирает через Kalkan, и повторяет вверх, пока есть ссылка AIA
// (у корня её нет). Локальные CA-файлы не нужны — только сеть.
func aiaWalk(leafPEM []byte) ([]CertDump, []string) {
	var dumps []CertDump
	var urls []string
	seen := map[string]bool{}
	cur := leafPEM
	for hop := 0; hop < 6; hop++ {
		url := caIssuerURL(toDER(cur))
		if url == "" {
			logf("  AIA: ссылки на издателя больше нет — достигнут корень")
			break
		}
		if seen[url] {
			break
		}
		seen[url] = true
		urls = append(urls, url)
		logf("  AIA: скачиваю издателя %s", url)
		body, err := httpGetCert(url)
		if err != nil {
			logf("  AIA: ошибка загрузки: %v", err)
			dumps = append(dumps, CertDump{Label: "AIA fetch FAILED: " + url})
			break
		}
		p := toPEM(body)
		logf("  AIA: разбор скачанного сертификата (%d байт)", len(body))
		dumps = append(dumps, CertDump{Label: "AIA fetched: " + url, Fields: certInfo(p)})
		cur = p
	}
	return dumps, urls
}

func readFile(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

// extractCmsSigners перебирает подписи (sigId 1-based) и разбирает сертификат
// каждого подписанта из CMS. Останавливается, когда очередной подписи нет.
func extractCmsSigners(cms []byte) []CertDump {
	var out []CertDump
	const bcap = 1 << 18
	cCms := C.CBytes(cms)
	defer C.free(cCms)
	for sigId := 1; sigId <= 8; sigId++ {
		buf := C.malloc(bcap)
		outLen := C.int(bcap)
		rc := C.probe_cert_from_cms((*C.char)(cCms), C.int(len(cms)), C.int(sigId),
			C.int(KC_IN_PEM|KC_OUT_PEM), (*C.char)(buf), &outLen)
		if rc != 0 || outLen <= 0 || int(outLen) >= bcap {
			C.free(buf)
			break
		}
		cert := trimNul(C.GoBytes(buf, outLen))
		C.free(buf)
		out = append(out, CertDump{Label: fmt.Sprintf("CMS signer #%d", sigId), Fields: certInfo(cert)})
	}
	return out
}

// extractXmlSigners — то же для XML.
func extractXmlSigners(xml []byte) []CertDump {
	var out []CertDump
	const bcap = 1 << 18
	cXml := C.CBytes(xml)
	defer C.free(cXml)
	for sigId := 1; sigId <= 8; sigId++ {
		buf := C.malloc(bcap)
		outLen := C.int(bcap)
		rc := C.probe_cert_from_xml((*C.char)(cXml), C.int(len(xml)), C.int(sigId),
			(*C.char)(buf), &outLen)
		if rc != 0 || outLen <= 0 || int(outLen) >= bcap {
			C.free(buf)
			break
		}
		cert := trimNul(C.GoBytes(buf, outLen))
		C.free(buf)
		out = append(out, CertDump{Label: fmt.Sprintf("XML signer #%d", sigId), Fields: certInfo(cert)})
	}
	return out
}

func fieldText(fields []FieldResult, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Text
		}
	}
	return ""
}

// afterEq возвращает часть значения после первого '=' (C-API отдаёт "имя=значение").
func afterEq(s string) string {
	if i := strings.IndexByte(s, '='); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return strings.TrimSpace(s)
}

// validateCert вызывает X509ValidateCertificate (CRL или OCSP).
func validateCert(cert []byte, validType int, path string, checkTime int64, wantOCSP bool) ValidationResult {
	const bcap = 1 << 16
	outInfo := C.malloc(bcap)
	defer C.free(outInfo)
	getOcsp := C.malloc(bcap)
	defer C.free(getOcsp)
	outLen := C.int(bcap)
	ocspLen := C.int(bcap)
	cCert := C.CBytes(cert)
	defer C.free(cCert)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	flag := 0
	if wantOCSP {
		flag = KC_GET_OCSP_RESPONSE
	}
	rc := C.probe_validate((*C.char)(cCert), C.int(len(cert)), C.int(validType), cPath,
		C.longlong(checkTime), (*C.char)(outInfo), &outLen, C.int(flag),
		(*C.char)(getOcsp), &ocspLen)
	res := ValidationResult{RC: hexS(rc)}
	if validType == KC_USE_CRL {
		res.Type = "CRL"
	} else {
		res.Type = "OCSP"
	}
	if outLen > 0 && int(outLen) < bcap {
		res.Info = string(trimNul(C.GoBytes(outInfo, outLen)))
	}
	if wantOCSP && ocspLen > 0 && int(ocspLen) < bcap {
		res.OCSPB64 = base64.StdEncoding.EncodeToString(C.GoBytes(getOcsp, ocspLen))
	}
	logf("валидация %s: %s %s", res.Type, res.RC, truncate(res.Info, 80))
	return res
}

func lastErr() string {
	const cap = 1 << 16
	buf := C.malloc(cap)
	defer C.free(buf)
	l := C.int(cap)
	C.probe_lasterr((*C.char)(buf), &l)
	if l <= 0 {
		return ""
	}
	return string(C.GoBytes(buf, l))
}

func main() {
	rep := Report{
		LibPath: os.Getenv("LIB_PATH"),
		KeyPath: os.Getenv("KEY_PATH"),
	}
	pass := os.Getenv("KEY_PASS")
	if rep.LibPath == "" || rep.KeyPath == "" {
		logf("нужны переменные окружения LIB_PATH, KEY_PATH, KEY_PASS")
		os.Exit(2)
	}

	// 1) Загрузка библиотеки
	errBuf := C.malloc(4096)
	defer C.free(errBuf)
	errLen := C.int(4096)
	cLib := C.CString(rep.LibPath)
	defer C.free(unsafe.Pointer(cLib))
	if rc := C.probe_load(cLib, (*C.char)(errBuf), &errLen); rc != 0 {
		msg := string(C.GoBytes(errBuf, errLen))
		logf("probe_load rc=%s: %s", hexS(rc), msg)
		os.Exit(1)
	}
	logf("библиотека загружена: %s", rep.LibPath)

	// 2) KC_Init
	rep.InitRC = hexS(C.probe_init())
	logf("KC_Init: %s", rep.InitRC)

	// 3) LoadKeyStore (PKCS12)
	aliasBuf := C.malloc(4096)
	defer C.free(aliasBuf)
	cPass := C.CString(pass)
	defer C.free(unsafe.Pointer(cPass))
	cCont := C.CString(rep.KeyPath)
	defer C.free(unsafe.Pointer(cCont))
	rcLoad := C.probe_loadkey(C.int(KCST_PKCS12), cPass, C.int(len(pass)),
		cCont, C.int(len(rep.KeyPath)), (*C.char)(aliasBuf), 4096)
	rep.LoadKeyRC = hexS(rcLoad)
	rep.Alias = C.GoString((*C.char)(aliasBuf))
	logf("LoadKeyStore: %s alias=%q", rep.LoadKeyRC, rep.Alias)
	if rcLoad != 0 {
		rep.Errors = append(rep.Errors, "LoadKeyStore: "+lastErr())
		emit(rep)
		return
	}

	// 4) Экспорт сертификата владельца (PEM)
	const certCap = 1 << 18
	certBuf := C.malloc(certCap)
	defer C.free(certBuf)
	certLen := C.int(certCap)
	cAlias := C.CString(rep.Alias)
	defer C.free(unsafe.Pointer(cAlias))
	rcExp := C.probe_export_cert(cAlias, C.int(KC_CERT_PEM), (*C.char)(certBuf), &certLen)
	rep.ExportCertRC = hexS(rcExp)
	var ownerCert []byte
	if rcExp == 0 && certLen > 0 {
		ownerCert = C.GoBytes(certBuf, certLen)
		rep.OwnerCertPEM = string(ownerCert)
		logf("экспорт сертификата: %s len=%d", rep.ExportCertRC, certLen)
		logf("--- разбор свойств сертификата владельца ---")
		rep.OwnerFields = certInfo(ownerCert)
	} else {
		rep.Errors = append(rep.Errors, "ExportCert: "+lastErr())
	}

	// 5) Подпись данных в CMS (attached, PEM)
	data := []byte("Hello, Қазақстан 2026 — тест ЭЦП / qoltanba probe")
	const signCap = 1 << 20
	signBuf := C.malloc(signCap)
	defer C.free(signBuf)
	signLen := C.int(signCap)
	cData := C.CBytes(data)
	defer C.free(cData)
	signFlags := KC_SIGN_CMS | KC_OUT_PEM | KC_NOCHECKCERTTIME
	rcSign := C.probe_sign_data(cAlias, C.int(signFlags),
		(*C.char)(cData), C.int(len(data)), (*C.uchar)(signBuf), &signLen)
	rep.SignRC = hexS(rcSign)
	var cms []byte
	if rcSign == 0 && signLen > 0 {
		cms = C.GoBytes(signBuf, signLen)
		rep.SignedCMSPEM = string(cms)
		logf("подпись CMS: %s len=%d", rep.SignRC, signLen)
	} else {
		rep.Errors = append(rep.Errors, "SignData: "+lastErr())
	}

	// 6) Проверка подписи + извлечение
	if cms != nil {
		const cap = 1 << 20
		outData := C.malloc(cap)
		defer C.free(outData)
		outVer := C.malloc(cap)
		defer C.free(outVer)
		outCert := C.malloc(cap)
		defer C.free(outCert)
		outDataLen := C.int(cap)
		outVerLen := C.int(cap)
		outCertLen := C.int(cap)
		cCms := C.CBytes(cms)
		defer C.free(cCms)
		emptyAlias := C.CString("")
		defer C.free(unsafe.Pointer(emptyAlias))

		// Эталон SDK: VerifyData вызывается с ТЕМИ ЖЕ флагами, что и подпись,
		// и получает исходные данные + подпись.
		rcVer := C.probe_verify_data(emptyAlias, C.int(signFlags),
			(*C.char)(cData), C.int(len(data)), (*C.uchar)(cCms), C.int(len(cms)),
			(*C.char)(outData), &outDataLen,
			(*C.char)(outVer), &outVerLen,
			0, (*C.char)(outCert), &outCertLen)
		rep.VerifyRC = hexS(rcVer)
		logf("проверка CMS: %s", rep.VerifyRC)
		if outVerLen > 0 {
			rep.VerifyInfo = string(trimNul(C.GoBytes(outVer, outVerLen)))
		}
		if outDataLen > 0 {
			rep.VerifiedData = string(trimNul(C.GoBytes(outData, outDataLen)))
		}
		// Разбор извлечённого сертификата подписанта — только при успешной
		// проверке и валидной длине (иначе в буфере мусор → SIGSEGV в либе).
		if rcVer == 0 && outCertLen > 0 && int(outCertLen) < cap {
			signerCert := trimNul(C.GoBytes(outCert, outCertLen))
			logf("--- разбор свойств извлечённого сертификата подписанта (len=%d) ---", len(signerCert))
			rep.SignerFields = certInfo(signerCert)
		} else if rcVer != 0 {
			rep.Errors = append(rep.Errors, "VerifyData: "+lastErr())
		}

		// 6a) Восстановление ОРИГИНАЛЬНОГО содержимого из attached-CMS:
		// проверяем ту же подпись, но БЕЗ передачи исходных данных (inData=NULL) —
		// у вложенной (attached) подписи содержимое возвращается в outData.
		{
			rbuf := C.malloc(cap)
			defer C.free(rbuf)
			vbuf := C.malloc(cap)
			defer C.free(vbuf)
			cbuf := C.malloc(cap)
			defer C.free(cbuf)
			rlen := C.int(cap)
			vlen := C.int(cap)
			clen := C.int(cap)
			// Входная подпись — PEM; выходное содержимое — как есть (без KC_OUT_PEM,
			// иначе либа пытается обернуть контент в PEM и отдаёт пусто).
			recFlags := KC_SIGN_CMS | KC_IN_PEM | KC_NOCHECKCERTTIME
			rc2 := C.probe_verify_data(emptyAlias, C.int(recFlags),
				nil, 0, (*C.uchar)(cCms), C.int(len(cms)),
				(*C.char)(rbuf), &rlen, (*C.char)(vbuf), &vlen,
				0, (*C.char)(cbuf), &clen)
			rep.RecoverContentRC = hexS(rc2)
			if rlen > 0 && int(rlen) < cap {
				rep.RecoveredContent = string(trimNul(C.GoBytes(rbuf, rlen)))
			}
			logf("восстановление содержимого из attached-CMS: %s len=%d", rep.RecoverContentRC, rlen)
		}

		// 7) Метка времени из подписи
		var t C.longlong
		rcTime := C.probe_time_from_sig((*C.char)(cCms), C.int(len(cms)), C.int(KC_IN_PEM), 0, &t)
		rep.TimeFromSigRC = hexS(rcTime)
		if rcTime == 0 && t > 0 {
			rep.TimeFromSig = time.Unix(int64(t), 0).Format(time.RFC3339)
		}
		logf("метка времени: %s %s", rep.TimeFromSigRC, rep.TimeFromSig)
	}

	// ===================== ЦЕПОЧКА СЕРТИФИКАТОВ =====================
	caDir := os.Getenv("CA_DIR")
	if caDir == "" {
		caDir = "/native/ca"
	}
	rootPem := readFile(caDir + "/root.pem")
	ncaPem := readFile(caDir + "/nca.pem")
	var ncaFields, rootFields []FieldResult
	if len(rep.OwnerFields) > 0 {
		rep.Chain = append(rep.Chain, CertDump{"leaf (владелец)", rep.OwnerFields})
	}
	if ncaPem != nil {
		logf("--- разбор промежуточного сертификата (НУЦ) ---")
		ncaFields = certInfo(ncaPem)
		rep.Chain = append(rep.Chain, CertDump{"intermediate (НУЦ)", ncaFields})
	}
	if rootPem != nil {
		logf("--- разбор корневого сертификата (КУЦ) ---")
		rootFields = certInfo(rootPem)
		rep.Chain = append(rep.Chain, CertDump{"root (КУЦ)", rootFields})
	}
	// Порядок цепочки по AUTH_KEY_ID -> SUBJ_KEY_ID.
	rep.ChainOrder = buildChainOrder(rep.Chain)

	// ===================== ДОСТРОЙКА ЦЕПОЧКИ ПО AIA =====================
	// Без локальных CA-файлов: скачиваем издателей по ссылке AIA из листа.
	if ownerCert != nil {
		logf("--- достройка цепочки по AIA (скачивание издателей из сети) ---")
		rep.AIAChain, rep.AIAUrls = aiaWalk(ownerCert)
	}

	// ===================== ВАЛИДАЦИЯ (CRL / OCSP) =====================
	if ownerCert != nil {
		// Подгружаем CA-сертификаты для построения цепочки доверия.
		loadCA := func(name string, t int) {
			p := C.CString(caDir + "/" + name)
			defer C.free(unsafe.Pointer(p))
			rc := C.probe_load_cert_file(p, C.int(t))
			logf("загрузка CA %s: %s", name, hexS(rc))
		}
		loadCA("root_test_gost_2022.cer", KC_CERT_CA)
		loadCA("nca_gost2022_test.cer", KC_CERT_INTERMEDIATE)

		checkTime := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix() // в пределах срока
		crl := os.Getenv("CRL_PATH")
		if crl == "" {
			crl = caDir + "/nca_gost2022_test.crl"
		}
		rep.Validations = append(rep.Validations, validateCert(ownerCert, KC_USE_CRL, crl, checkTime, false))
		rep.Validations = append(rep.Validations, validateCert(ownerCert, KC_USE_OCSP, "http://test.pki.gov.kz/ocsp/", checkTime, true))
	}

	// ===================== СЕРТИФИКАТ ПОДПИСАНТА ИЗ CMS =====================
	if cms != nil {
		const bcap = 1 << 18
		out := C.malloc(bcap)
		defer C.free(out)
		outLen := C.int(bcap)
		cCms := C.CBytes(cms)
		defer C.free(cCms)
		rc := C.probe_cert_from_cms((*C.char)(cCms), C.int(len(cms)), 1, C.int(KC_IN_PEM|KC_OUT_PEM),
			(*C.char)(out), &outLen)
		rep.CmsSignerCertRC = hexS(rc)
		logf("извлечение сертификата из CMS: %s", rep.CmsSignerCertRC)
		if rc == 0 && outLen > 0 && int(outLen) < bcap {
			logf("--- разбор сертификата подписанта из CMS ---")
			rep.CmsSignerFields = certInfo(trimNul(C.GoBytes(out, outLen)))
		}
	}

	// ===================== XML: SIGN / VERIFY / EXTRACT =====================
	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root><data>тест XML ЭЦП kalkan</data></root>`)
	{
		const bcap = 1 << 20
		out := C.malloc(bcap)
		defer C.free(out)
		outLen := C.int(bcap)
		cXml := C.CBytes(xml)
		defer C.free(cXml)
		emptyC := C.CString("")
		defer C.free(unsafe.Pointer(emptyC))
		rc := C.probe_sign_xml(cAlias, C.int(KC_NOCHECKCERTTIME), (*C.char)(cXml), C.int(len(xml)),
			(*C.uchar)(out), &outLen, emptyC, emptyC, emptyC)
		rep.XmlSignRC = hexS(rc)
		logf("подпись XML: %s len=%d", rep.XmlSignRC, outLen)
		if rc == 0 && outLen > 0 && int(outLen) < bcap {
			signedXml := trimNul(C.GoBytes(out, outLen))
			cSigned := C.CBytes(signedXml)
			defer C.free(cSigned)

			// verify
			vinfo := C.malloc(bcap)
			defer C.free(vinfo)
			vlen := C.int(bcap)
			rcV := C.probe_verify_xml(emptyC, C.int(KC_NOCHECKCERTTIME), (*C.char)(cSigned),
				C.int(len(signedXml)), (*C.char)(vinfo), &vlen)
			rep.XmlVerifyRC = hexS(rcV)
			if vlen > 0 && int(vlen) < bcap {
				rep.XmlVerifyInfo = string(trimNul(C.GoBytes(vinfo, vlen)))
			}
			logf("проверка XML: %s", rep.XmlVerifyRC)

			// алгоритм подписи
			salg := C.malloc(4096)
			defer C.free(salg)
			slen := C.int(4096)
			rcA := C.probe_sigalg_from_xml((*C.char)(cSigned), C.int(len(signedXml)), (*C.char)(salg), &slen)
			rep.XmlSigAlgRC = hexS(rcA)
			if slen > 0 && int(slen) < 4096 {
				rep.XmlSigAlg = string(trimNul(C.GoBytes(salg, slen)))
			}

			// сертификат из XML
			xcert := C.malloc(bcap)
			defer C.free(xcert)
			xlen := C.int(bcap)
			rcC := C.probe_cert_from_xml((*C.char)(cSigned), C.int(len(signedXml)), 1, (*C.char)(xcert), &xlen)
			rep.XmlCertRC = hexS(rcC)
			if rcC == 0 && xlen > 0 && int(xlen) < bcap {
				logf("--- разбор сертификата подписанта из XML ---")
				rep.XmlSignerFields = certInfo(trimNul(C.GoBytes(xcert, xlen)))
			}
		} else {
			rep.Errors = append(rep.Errors, "SignXML: "+lastErr())
		}
	}

	// ===================== МНОЖЕСТВЕННАЯ ПОДПИСЬ (ДВА ЧЕЛОВЕКА) =====================
	key2 := os.Getenv("KEY2_PATH")
	pass2 := os.Getenv("KEY2_PASS")
	if pass2 == "" {
		pass2 = pass
	}
	if key2 != "" {
		logf("=== множественная подпись: подписант A + подписант B (%s) ===", key2)
		const bcap = 1 << 20
		cData2 := C.CBytes(data)
		defer C.free(cData2)
		cXml2 := C.CBytes(xml)
		defer C.free(cXml2)
		emptyC2 := C.CString("")
		defer C.free(unsafe.Pointer(emptyC2))

		// 1) Подписант A (уже загружен): detached CMS + XML
		aBuf := C.malloc(bcap)
		defer C.free(aBuf)
		aLen := C.int(bcap)
		faDet := KC_SIGN_CMS | KC_OUT_PEM | KC_DETACHED_DATA | KC_NOCHECKCERTTIME
		rcA := C.probe_sign_data(cAlias, C.int(faDet), (*C.char)(cData2), C.int(len(data)), (*C.uchar)(aBuf), &aLen)
		var cmsA []byte
		if rcA == 0 && aLen > 0 {
			cmsA = trimNul(C.GoBytes(aBuf, aLen))
		}
		logf("подпись A (detached CMS): %s len=%d", hexS(rcA), aLen)

		xaBuf := C.malloc(bcap)
		defer C.free(xaBuf)
		xaLen := C.int(bcap)
		rcXA := C.probe_sign_xml(cAlias, C.int(KC_NOCHECKCERTTIME), (*C.char)(cXml2), C.int(len(xml)),
			(*C.uchar)(xaBuf), &xaLen, emptyC2, emptyC2, emptyC2)
		var xmlA []byte
		if rcXA == 0 && xaLen > 0 {
			xmlA = trimNul(C.GoBytes(xaBuf, xaLen))
		}
		logf("подпись A (XML): %s len=%d", hexS(rcXA), xaLen)

		// 2) Загрузка ключа подписанта B
		cKey2 := C.CString(key2)
		defer C.free(unsafe.Pointer(cKey2))
		cPass2 := C.CString(pass2)
		defer C.free(unsafe.Pointer(cPass2))
		alias2 := C.malloc(4096)
		defer C.free(alias2)
		rcL2 := C.probe_loadkey(C.int(KCST_PKCS12), cPass2, C.int(len(pass2)), cKey2, C.int(len(key2)), (*C.char)(alias2), 4096)
		logf("загрузка ключа B: %s", hexS(rcL2))
		emptyAlias2 := C.CString("")
		defer C.free(unsafe.Pointer(emptyAlias2))

		// 3) Ко-подпись CMS: B добавляет свою подпись к cmsA
		if cmsA != nil && rcL2 == 0 {
			abBuf := C.malloc(bcap)
			defer C.free(abBuf)
			abLen := C.int(bcap)
			cCmsA := C.CBytes(cmsA)
			defer C.free(cCmsA)
			fbDet := KC_SIGN_CMS | KC_IN_PEM | KC_OUT_PEM | KC_DETACHED_DATA | KC_NOCHECKCERTTIME
			rcAB := C.probe_sign_data_co(emptyAlias2, C.int(fbDet), (*C.char)(cData2), C.int(len(data)),
				(*C.uchar)(cCmsA), C.int(len(cmsA)), (*C.uchar)(abBuf), &abLen)
			rep.MultiCmsSignRC = hexS(rcAB)
			logf("ко-подпись B (CMS): %s len=%d", rep.MultiCmsSignRC, abLen)
			if rcAB == 0 && abLen > 0 {
				cmsAB := trimNul(C.GoBytes(abBuf, abLen))
				cCmsAB := C.CBytes(cmsAB)
				defer C.free(cCmsAB)
				vd := C.malloc(bcap)
				defer C.free(vd)
				vi := C.malloc(bcap)
				defer C.free(vi)
				vc := C.malloc(bcap)
				defer C.free(vc)
				vdl := C.int(bcap)
				vil := C.int(bcap)
				vcl := C.int(bcap)
				rcV := C.probe_verify_data(emptyAlias2, C.int(fbDet), (*C.char)(cData2), C.int(len(data)),
					(*C.uchar)(cCmsAB), C.int(len(cmsAB)), (*C.char)(vd), &vdl, (*C.char)(vi), &vil, 0, (*C.char)(vc), &vcl)
				rep.MultiCmsVerifyRC = hexS(rcV)
				if vil > 0 && int(vil) < bcap {
					rep.MultiCmsVerifyInfo = string(trimNul(C.GoBytes(vi, vil)))
				}
				logf("проверка мультиподписи CMS: %s", rep.MultiCmsVerifyRC)
				rep.MultiCmsSigners = extractCmsSigners(cmsAB)
				logf("подписантов в CMS извлечено: %d", len(rep.MultiCmsSigners))
			}
		}

		// 4) Ко-подпись XML: B подписывает уже подписанный A документ
		if xmlA != nil && rcL2 == 0 {
			xabBuf := C.malloc(bcap)
			defer C.free(xabBuf)
			xabLen := C.int(bcap)
			cXmlA := C.CBytes(xmlA)
			defer C.free(cXmlA)
			rcXAB := C.probe_sign_xml(emptyAlias2, C.int(KC_NOCHECKCERTTIME), (*C.char)(cXmlA), C.int(len(xmlA)),
				(*C.uchar)(xabBuf), &xabLen, emptyC2, emptyC2, emptyC2)
			rep.MultiXmlSignRC = hexS(rcXAB)
			logf("ко-подпись B (XML): %s len=%d", rep.MultiXmlSignRC, xabLen)
			if rcXAB == 0 && xabLen > 0 {
				xmlAB := trimNul(C.GoBytes(xabBuf, xabLen))
				cXmlAB := C.CBytes(xmlAB)
				defer C.free(cXmlAB)
				vi := C.malloc(bcap)
				defer C.free(vi)
				vil := C.int(bcap)
				rcV := C.probe_verify_xml(emptyAlias2, C.int(KC_NOCHECKCERTTIME), (*C.char)(cXmlAB), C.int(len(xmlAB)),
					(*C.char)(vi), &vil)
				rep.MultiXmlVerifyRC = hexS(rcV)
				if vil > 0 && int(vil) < bcap {
					rep.MultiXmlVerifyInfo = string(trimNul(C.GoBytes(vi, vil)))
				}
				logf("проверка мультиподписи XML: %s", rep.MultiXmlVerifyRC)
				rep.MultiXmlSigners = extractXmlSigners(xmlAB)
				logf("подписантов в XML извлечено: %d", len(rep.MultiXmlSigners))
			}
		}
	}

	C.probe_finalize()
	emit(rep)
}

// buildChainOrder упорядочивает разобранные сертификаты по цепочке доверия:
// AUTH_KEY_ID сертификата == SUBJ_KEY_ID его издателя. Возвращает CN по порядку
// leaf -> ... -> root.
func buildChainOrder(chain []CertDump) []string {
	skidTo := map[string]CertDump{}
	for _, c := range chain {
		skidTo[afterEq(fieldText(c.Fields, "SUBJ_KEY_ID"))] = c
	}
	// стартуем с leaf: сертификат, чей SKID никто другой не указывает как AKID.
	var start *CertDump
	for i := range chain {
		skid := afterEq(fieldText(chain[i].Fields, "SUBJ_KEY_ID"))
		referenced := false
		for j := range chain {
			if j == i {
				continue
			}
			if afterEq(fieldText(chain[j].Fields, "AUTH_KEY_ID")) == skid {
				referenced = true
				break
			}
		}
		if !referenced {
			start = &chain[i]
			break
		}
	}
	var order []string
	seen := map[string]bool{}
	cur := start
	for cur != nil {
		cn := afterEq(fieldText(cur.Fields, "SUBJECT_COMMONNAME"))
		order = append(order, cur.Label+": "+cn)
		akid := afterEq(fieldText(cur.Fields, "AUTH_KEY_ID"))
		skid := afterEq(fieldText(cur.Fields, "SUBJ_KEY_ID"))
		if akid == "" || akid == skid || seen[akid] {
			break // корень (self) или конец
		}
		seen[skid] = true
		next, ok := skidTo[akid]
		if !ok {
			break
		}
		cur = &next
	}
	return order
}

func emit(rep Report) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(rep)
}
