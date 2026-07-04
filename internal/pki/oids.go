// Package pki — материализованные OID-справочники НУЦ/КУЦ РК и вспомогательные
// таблицы алгоритмов, нужные для разбора сертификатов и подписи.
//
// Имена OID берутся из официального государственного справочника
// (https://root.gov.kz/oid/, вся арка 1.2.398), снимок которого лежит рядом в
// oids-nuc.json и встраивается через go:embed. Семантический маппинг ролей в
// keyUser — курируемый (ниже), чтобы не зависеть от точных формулировок имён.
//
// Регенерация имён: tools/oidgen/fetch_oids.py.
package pki

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

// ============================ ОФИЦИАЛЬНЫЕ ИМЕНА OID ============================

//go:embed oids-nuc.json
var oidsJSON []byte

type oidRegistry struct {
	Source   string            `json:"source"`
	Count    int               `json:"count"`
	Roles    map[string]string `json:"roles"`
	Policies map[string]string `json:"policies"`
	All      map[string]string `json:"all"`
}

var (
	regOnce sync.Once
	reg     oidRegistry
)

func registry() *oidRegistry {
	regOnce.Do(func() { _ = json.Unmarshal(oidsJSON, &reg) })
	return &reg
}

// Name возвращает официальное название OID из справочника КУЦ РК (пусто, если нет).
func Name(oid string) string { return registry().All[oid] }

// RegistrySource — URL официального источника имён.
func RegistrySource() string { return registry().Source }

// ============================ РОЛИ (keyUser) ============================

// KeyUser — роль/тип владельца сертификата (паритет с NCANode CertificateKeyUser).
type KeyUser string

const (
	KeyUserIndividual       KeyUser = "INDIVIDUAL"
	KeyUserOrganization     KeyUser = "ORGANIZATION"
	KeyUserCEO              KeyUser = "CEO"
	KeyUserCanSign          KeyUser = "CAN_SIGN"
	KeyUserCanSignFinancial KeyUser = "CAN_SIGN_FINANCIAL"
	KeyUserHR               KeyUser = "HR"
	KeyUserEmployee         KeyUser = "EMPLOYEE"
	KeyUserInfosystem       KeyUser = "INFOSYSTEM"
	KeyUserTreasuryClient   KeyUser = "TREASURY_CLIENT"
	KeyUserNCAAdmin         KeyUser = "NCA_ADMIN"
	KeyUserNCAManager       KeyUser = "NCA_MANAGER"
	KeyUserNCAOperator      KeyUser = "NCA_OPERATOR"
	KeyUserIdentCON         KeyUser = "IDENTIFICATION_CON"
	KeyUserIdentRemote      KeyUser = "IDENTIFICATION_REMOTE"
	KeyUserIdentDigitalID   KeyUser = "IDENTIFICATION_DIGITAL_ID"
	KeyUserIdentAIPlatform  KeyUser = "IDENTIFICATION_AI_PLATFORM"
)

// Точный маппинг OID расширения extendedKeyUsage → роль (по официальному реестру
// https://root.gov.kz/oid/, ветка 1.2.398.3.3.4.*).
var ekuRoleExact = map[string]KeyUser{
	"1.2.398.3.3.4.1.1":    KeyUserIndividual,       // Физическое лицо
	"1.2.398.3.3.4.1.2":    KeyUserOrganization,     // Юридическое лицо/СП
	"1.2.398.3.3.4.1.2.1":  KeyUserCEO,              // Первый руководитель
	"1.2.398.3.3.4.1.2.2":  KeyUserCanSign,          // Право подписи
	"1.2.398.3.3.4.1.2.3":  KeyUserCanSignFinancial, // Право подписи фин. документов
	"1.2.398.3.3.4.1.2.4":  KeyUserHR,               // Сотрудник отдела кадров
	"1.2.398.3.3.4.1.2.5":  KeyUserEmployee,         // Сотрудник организации
	"1.2.398.3.3.4.1.2.6":  KeyUserInfosystem,       // Информационная система ЮЛ
	"1.2.398.3.3.4.2.1":    KeyUserNCAAdmin,         // Администратор НУЦ РК
	"1.2.398.3.3.4.2.2":    KeyUserNCAManager,       // Менеджер НУЦ РК
	"1.2.398.3.3.4.2.3":    KeyUserNCAOperator,      // Оператор НУЦ РК
	"1.2.398.3.3.4.3.1":    KeyUserIdentCON,         // Идентификация через ЦОН
	"1.2.398.3.3.4.3.2":    KeyUserIdentRemote,      // Удалённая идентификация
	"1.2.398.3.3.4.3.2.1":  KeyUserIdentDigitalID,   // Digital-ID
	"1.2.398.3.3.4.3.2.2":  KeyUserIdentAIPlatform,  // AI Platform
	"1.2.398.5.19.1.2.2.1": KeyUserTreasuryClient,   // Казначейство (ИС К2)
}

// Префиксы: конкретные ИС (сотни узлов 1.2.398.3.3.4.1.2.6.*) → INFOSYSTEM.
const infosystemPrefix = "1.2.398.3.3.4.1.2.6"

// KeyUserForOID определяет роль по одному OID из EKU. Пусто, если не роль НУЦ.
func KeyUserForOID(oid string) KeyUser {
	if r, ok := ekuRoleExact[oid]; ok {
		return r
	}
	if oid == infosystemPrefix || strings.HasPrefix(oid, infosystemPrefix+".") {
		return KeyUserInfosystem
	}
	return ""
}

// KeyUsersFromEKU извлекает роли из набора OID расширения extendedKeyUsage
// (с сохранением порядка и без дублей).
func KeyUsersFromEKU(ekuOIDs []string) []KeyUser {
	var out []KeyUser
	seen := map[KeyUser]bool{}
	for _, oid := range ekuOIDs {
		if r := KeyUserForOID(strings.TrimSpace(oid)); r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// ============================ ТИП ВЛАДЕЛЬЦА ============================

type OwnerType string

const (
	OwnerIndividual  OwnerType = "INDIVIDUAL"   // физлицо
	OwnerLegalPerson OwnerType = "LEGAL_PERSON" // сотрудник ЮЛ (ФИО/ИИН + OU=BIN)
	OwnerInfosystem  OwnerType = "INFOSYSTEM"   // ИС (OU=BIN, без ФИО/ИИН)
	OwnerUnknown     OwnerType = "UNKNOWN"
)

// OwnerTypeFrom выводит тип владельца по наличию БИН(OU) и ФИО/ИИН (подтверждено
// пробником: физлицо — без OU=BIN; ИС — есть BIN, нет ФИО/ИИН).
func OwnerTypeFrom(hasBIN, hasNameOrIIN bool) OwnerType {
	switch {
	case !hasBIN && hasNameOrIIN:
		return OwnerIndividual
	case hasBIN && hasNameOrIIN:
		return OwnerLegalPerson
	case hasBIN && !hasNameOrIIN:
		return OwnerInfosystem
	default:
		return OwnerUnknown
	}
}

// ============================ ПОЛИТИКИ TSA ============================

type TsaPolicy string

const (
	TSAGost     TsaPolicy = "TSA_GOST_POLICY"     // ГОСТ 34.311-95
	TSARSA      TsaPolicy = "TSA_RSA_POLICY"      // RSA-SHA256
	TSAGostGT   TsaPolicy = "TSA_GOSTGT_POLICY"   // GOST GT
	TSAGost2015 TsaPolicy = "TSA_GOST2015_POLICY" // ГОСТ 34.311-2015 (дефолт)
)

// OID политик TSA (ветка 1.2.398.3.3.2.6.*).
var tsaPolicyID = map[TsaPolicy]string{
	TSAGost:     "1.2.398.3.3.2.6.1",
	TSARSA:      "1.2.398.3.3.2.6.2",
	TSAGostGT:   "1.2.398.3.3.2.6.3",
	TSAGost2015: "1.2.398.3.3.2.6.4",
}

// DefaultTSAPolicy — политика по умолчанию при запросе метки времени без явной.
const DefaultTSAPolicy = TSAGost2015

// TSAPolicyID возвращает OID-строку политики TSA.
func TSAPolicyID(p TsaPolicy) string { return tsaPolicyID[p] }

// OID unsigned-атрибута метки времени в CMS (RFC 3161, id_aa_signatureTimeStampToken).
const TimestampTokenAttrOID = "1.2.840.113549.1.9.16.2.14"

// ============================ АЛГОРИТМЫ ПОДПИСИ/ХЕША ============================

// OID алгоритмов подписи сертификата (значение cert.SignatureAlgorithm).
const (
	SignSHA1RSA      = "1.2.840.113549.1.1.5"
	SignSHA256RSA    = "1.2.840.113549.1.1.11"
	SignGOST2015_256 = "1.2.398.3.10.1.1.2.3.1"
	SignGOST2015_512 = "1.2.398.3.10.1.1.2.3.2"
)

// OID дайджестов.
const (
	DigestSHA1         = "1.3.14.3.2.26"
	DigestSHA256       = "2.16.840.1.101.3.4.2.1"
	DigestGOST34311_95 = "1.2.398.3.10.1.1.1.1" // старый ГОСТ Р 34.11-94 (kalkan)
	// Дайджесты ГОСТ-2015 (кириллические имена kalkan DIGEST_GOST3411_2015_256/512);
	// числовой OID отдаёт сама либа при выборе по флагам — при необходимости уточнить.
	DigestGOST2015_256 = "GOST3411_2015_256"
	DigestGOST2015_512 = "GOST3411_2015_512"
)

// DigestOIDForSignOID — дайджест по алгоритму подписи (как в NCANode Util).
func DigestOIDForSignOID(signOID string) string {
	switch signOID {
	case SignSHA1RSA:
		return DigestSHA1
	case SignSHA256RSA:
		return DigestSHA256
	case SignGOST2015_256:
		return DigestGOST2015_256
	case SignGOST2015_512:
		return DigestGOST2015_512
	default:
		return DigestGOST34311_95 // старый ГОСТ по умолчанию
	}
}

// hash OID → человекочитаемое имя (для TSP; таблица TSPAlgorithms + kalkan ГОСТ).
var hashNameByOID = map[string]string{
	"1.2.840.113549.2.5":     "MD5",
	"1.3.14.3.2.26":          "SHA1",
	"2.16.840.1.101.3.4.2.4": "SHA224",
	"2.16.840.1.101.3.4.2.1": "SHA256",
	"2.16.840.1.101.3.4.2.2": "SHA384",
	"2.16.840.1.101.3.4.2.3": "SHA512",
	"1.3.36.3.2.2":           "RIPEMD128",
	"1.3.36.3.2.1":           "RIPEMD160",
	"1.3.36.3.2.3":           "RIPEMD256",
	"1.2.398.3.10.1.1.1.1":   "GOST34311GT",
	"1.2.398.3.10.1.1.1":     "GOST34311",
}

// HashNameForOID возвращает имя хеш-алгоритма по OID (пусто, если неизвестен).
func HashNameForOID(oid string) string { return hashNameByOID[oid] }

// URI-пространства имён XMLDSig.
const (
	xmldsigMore    = "http://www.w3.org/2001/04/xmldsig-more#"
	xmlencSHA256   = "http://www.w3.org/2001/04/xmlenc#sha256"
	pkigovkzURNPfx = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:"
)

// XMLSignURIs возвращает (signatureMethodURI, digestMethodURI) для XMLDSig по OID
// алгоритма подписи сертификата (как KalkanUtil.getSignMethodByOID).
func XMLSignURIs(signOID string) (sign, digest string) {
	switch signOID {
	case SignSHA1RSA:
		return xmldsigMore + "rsa-sha1", xmldsigMore + "sha1"
	case SignSHA256RSA:
		return xmldsigMore + "rsa-sha256", xmlencSHA256
	case SignGOST2015_256:
		return pkigovkzURNPfx + "gostr34102015-gostr34112015-256",
			pkigovkzURNPfx + "gostr34112015-256"
	case SignGOST2015_512:
		return pkigovkzURNPfx + "gostr34102015-gostr34112015-512",
			pkigovkzURNPfx + "gostr34112015-512"
	default: // старый ГОСТ 34.310/34.311
		return xmldsigMore + "gost34310-gost34311", xmldsigMore + "gost34311"
	}
}

// ============================ АТРИБУТЫ DN → ПОЛЯ SUBJECT ============================

// Каноничные ключи RDN → имя поля субъекта (по правилам NCANode; сравнение
// ключей регистронезависимо, значения ИИН/БИН режутся по префиксу).
var dnAttrField = map[string]string{
	"CN":               "commonName",
	"SURNAME":          "lastName",
	"SN":               "lastName", // некоторые провайдеры отдают SN как surname
	"GIVENNAME":        "surName",
	"G":                "surName",
	"SERIALNUMBER":     "serialNumber", // содержит IIN...
	"O":                "organization",
	"OU":               "organizationUnit", // содержит BIN...
	"C":                "country",
	"L":                "locality",
	"S":                "state",
	"ST":               "state",
	"E":                "email",
	"EMAILADDRESS":     "email",
	"BUSINESSCATEGORY": "businessCategory",
	"DC":               "domainComponent",
}

// DN attribute type OID → каноничный ключ (когда провайдер отдаёт OID.x.y.z).
var dnOIDToKey = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SURNAME",
	"2.5.4.42":                   "GIVENNAME",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "S",
	"2.5.4.15":                   "BUSINESSCATEGORY",
	"1.2.840.113549.1.9.1":       "E",
	"0.9.2342.19200300.100.1.25": "DC",
}

// DNField возвращает имя поля субъекта по ключу RDN (CN/OU/…) либо по OID.
func DNField(key string) string {
	k := strings.ToUpper(strings.TrimSpace(key))
	k = strings.TrimPrefix(k, "OID.")
	if canon, ok := dnOIDToKey[k]; ok {
		k = canon
	}
	return dnAttrField[k]
}

// Префиксы значений (ИИН в SERIALNUMBER, БИН в OU) — режутся при разборе.
const (
	IINPrefix = "IIN"
	BINPrefix = "BIN"
)

// GenderFromIIN выводит пол из ИИН (7-я цифра: нечёт=муж, чёт=жен; 0 — не задан).
// В NCANode это поле не заполняется — вычисляем сами как улучшение.
func GenderFromIIN(iin string) string {
	if len(iin) < 7 {
		return "NONE"
	}
	c := iin[6]
	if c < '0' || c > '9' {
		return "NONE"
	}
	switch (c - '0') % 2 {
	case 1:
		return "MALE"
	case 0:
		if c == '0' {
			return "NONE"
		}
		return "FEMALE"
	}
	return "NONE"
}
