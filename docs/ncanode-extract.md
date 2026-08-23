# Экстракт из исходников NCANode v3 — всё, что нам потребуется

Полный разбор open-source сервиса **NCANode** (`ncanode-kz/NCANode`, Java/Spring)
по исходникам (95 java-файлов, ~3K строк ядра). Цель — извлечь все правила,
таблицы OID, алгоритмы, форматы, конфиг и зависимости, чтобы воспроизвести (и
превзойти) их функциональность в нашем Go-сервисе поверх нативного Kalkan C-API.

> NCANode — обёртка над **тем же криптоядром Kalkan** (`KalkanProvider`, Java JCE).
> Он НЕ зовёт `X509CertificateGetInfo`, а строит `X509Certificate` через провайдер
> и парсит **строковый DN** (`X500Principal.toString()`, RFC2253) + читает
> расширения через BouncyCastle-подобный ASN.1. У нас — нативный C-API +
> собственный разбор DER: данные те же или полнее.

Разделы ниже (каждый — отдельный агент по коду):
1. [Модель сертификата и парсинг](#раздел-1--модель-сертификата)
2. [CMS и метки времени (TSP)](#раздел-2--cms-и-tsp)
3. [XML / WSSE / ключи](#раздел-3--xml--wsse--ключи)
4. [OCSP / CRL / CA / конфигурация](#раздел-4--ocsp--crl--ca--конфигурация)
5. [PDF / JWT / API / ошибки / зависимости](#раздел-5--pdf--jwt--api)

---

## Сводка ключевых фактов (cross-cutting)

- **Сертификат.** DN→поля через `LdapName` (регистронезависимо); `state` только из
  `S`, `email` из `E`/`EMAILADDRESS`; ИИН = срез `^IIN` из `serialNumber`, БИН =
  срез `^BIN` из `serialNumber`/`OU`. `serialNumber` серта = `BigInteger.toString(16)`
  (hex без ведущих нулей) — критично для совпадения. `keyUser` — 15 OID НУЦ
  `1.2.398.3.3.4.*` из ExtendedKeyUsage. `keyUsage` → SIGN/AUTH/UNKNOWN по битам.
  **`gender` в v3 не вычисляется** (всегда null) — формулу из ИИН приводим как
  улучшение. `valid` требует найденного актуального issuer из CA-кэша.
- **CMS/TSP.** TSP-imprint считается от **SignatureValue подписанта** (не от
  контента!); токен — unsigned attribute OID `1.2.840.113549.1.9.16.2.14`. Политики
  TSA: база `1.2.398.3.3.2.6`, GOST=`.1`, RSA=`.2`, GOSTGT=`.3`, **GOST2015=`.4`
  (дефолт)**. Digest CMS — по OID алгоритма серта (2015-256/512); **hash TSP-запроса
  для любого GOST = старый GOST34311**. Co-sign: дедуп/неперезапись TSP по SID.
- **XML.** Обязателен `KncaXS.loadXMLSecurity()`. URI алгоритма — по `getSigAlgOID`
  (GOST-2015 → `pkigovkz`-URI). Transforms = [enveloped, **C14N с комментариями**],
  KeyInfo = X509Certificate, мультиподпись LIFO. В v3 вместо signNodeId —
  `referenceUri`. **WSSE**: exclusive-c14n **без** комментариев, серт через
  `SecurityTokenReference/KeyIdentifier` (не BinarySecurityToken), Body по `wsu:Id`,
  `mustUnderstand=1`.
- **OCSP/CRL/CA.** OCSP POST на URL из конфига (**AIA не используется**), CertID
  SHA-256, nonce 8 байт; **подпись ответа и thisUpdate/nextUpdate НЕ проверяются**
  (это наш повод улучшить). CRL — файловый кэш, TTL (full 1440м/delta 60м),
  `X509CRL.isRevoked`, delta раньше full, подпись/nextUpdate не валидируются. CA —
  из `NCANODE_CA_URL` (6 дефолтов), кэш `ca/*.cer`, `@Scheduled`+`@Retryable`, при
  сбое `System.exit(32)`.
- **Конфиг.** Порт **14579**; http-клиент connectionTtl 10с, **без** connect/read
  таймаутов; прокси Basic-auth; TSP retries=3; TaskScheduler pool=10; провайдер —
  `new KalkanProvider()`+`Security.addProvider`+`KncaXS`. Пути к сертам НУЦ — внутри
  jar (у нас — BYOL).
- **PDF.** **Apache PDFBox 2.0.29 (Apache-2.0)** — сознательно не iText (AGPL). PDF-
  слой только строит структуру (incremental update, `/ByteRange`,
  `SubFilter=ETSI.CAdES.detached`), а подпись — **detached CMS через нативный
  Kalkan**. PAdES/CAdES.
- **JWT.** Форк `kz.gov.pki:java-jwt:4.4.0` (auth0 java-jwt + алгоритмы GG2015/GG2004).
  Стандартный `header.payload.signature`; header только `alg`+`typ`; **x5c не
  используется** — серт для verify приходит отдельным полем `key`. Неверная подпись
  при decode → `200 { valid:false }`.
- **API/ошибки.** 15 POST + GET `/`; success наследует `StatusResponse{status,message}`;
  `revocationCheck` по умолчанию пуст (отзыв не проверяется!). Advice:
  `ClientException`=400, `NoSignaturesFoundException`=404, прочее=500,
  `ErrorResponse{status,message,details?}`.

---

## Что берём в наш проект (Go-импликации)

**Переиспользуем 1:1 (таблицы/правила — не код):**
- Таблицы OID: sign→digest, hash-OID→имя, **keyUser (15 OID)**, TSA-политики,
  алгоритм-URI для XML. → в `internal/pki/oids.go`.
- Правила парсинга DN → subject (CN/SN/GIVENNAME/serialNumber(ИИН)/OU(БИН)/O/C/L/S/BC/DC/E).
- keyUsage-биты → SIGN/AUTH/UNKNOWN; формат `serialNumber` = hex.
- Структуры CMS/TSP (imprint от SignatureValue, unsigned-attr OID), XML-transforms,
  WSSE-структуру, OCSP/CRL/CA-поток, набор эндпоинтов и DTO, маппинг ошибок.

**Улучшаем над NCANode (закрываем их слабые места):**
- Проверять **подпись OCSP-ответа и thisUpdate/nextUpdate** (они пропускают).
- Валидировать **подпись CRL и nextUpdate**.
- Возвращать **полную цепочку** `signers[].chain` (они — только лист).
- **Вычислять gender** из ИИН (у них null).
- Больше полей серта (AKI/SKI/policies/BC/DC/EKU-список) — см. `docs/COMPARISON-ncanode.md`.

**Зависимости для Go (кандидаты):**
- PDF: `pdfcpu` (Apache-2.0) или `digitorus/pdfsign` (MIT) — только для ByteRange/
  incremental; ГОСТ-CMS/TSP — через наш Kalkan-слой.
- JWT: реализуем сами (`header.payload` → `HashData`+`SignHash` → base64url); формат
  `alg` — согласовать (см. §5).
- ASN.1: `encoding/asn1` + собственный разбор ГОСТ TSP-токена / TSTInfo (нативный
  `KC_GetTimeFromSig` даёт только genTime — остальные поля TSP парсим сами).
- OCSP/CRL: разбор через свой ASN.1 (стандартные Go-либы могут не знать ГОСТ-OID).

---

# Раздел 1 — Модель сертификата

## NCANode → разбор сертификата (извлечение для Go-сервиса поверх нативного Kalkan C-API)

Источники (прочитаны полностью):
- `CertificateWrapper.java` — основной разбор, DN→Subject, keyUser, isValid, CRL-список.
- `CertificateService.java` — оркестрация info/verify, attachValidationData, load().
- `Util.java`, `KalkanUtil.java` — таблицы sign/digest OID, хэш-алгоритмы.
- `dto/certificate/*` — все DTO (CertificateInfo, CertificateSubject, KeyUser, KeyUsage, Gender, RevocationStatus, Revocation).
- Доп.: `CaService.java` (источник issuer-серта), `CrlStatus.java`, `OcspStatus.java`.

> ВАЖНО про источник данных: NCANode НЕ использует нативный `X509CertificateGetInfo`. Он строит X509Certificate через `CertificateFactory.getInstance("X.509", KalkanProvider)` и читает поля стандартным JCA/BouncyCastle API. Subject/Issuer берутся как строка DN из `X500Principal.toString()` (RFC 2253) и парсятся `javax.naming.ldap.LdapName`. Для вашего Go-сервиса это значит: правила ниже нужно применять к **строковому DN в формате RFC2253/RFC4514**, а не к сырому DER (хотя семантика RDN та же).

---

## 1. Парсинг DN → CertificateSubject (`createCertificateSubjectFromDn`)

Вход: `cert.getSubjectX500Principal().toString()` (и то же для issuer). Парсер: `new LdapName(dn)`, итерация по `rdn.getType()` (сравнение **регистронезависимо**, `equalsIgnoreCase`). Значение — `(String) rdn.getValue()`.

Таблица маппинга RDN-ключ → поле CertificateSubject (ТОЧНО как в коде, это единственные обрабатываемые ключи):

| RDN type (ci) | Поле DTO | Преобразование |
|---|---|---|
| `CN` | `commonName` | как есть |
| `SURNAME` | `surName` | как есть |
| `SERIALNUMBER` | `iin` **или** `bin` | см. ниже |
| `C` | `country` | как есть |
| `L` | `locality` | как есть |
| `S` | `state` | как есть (ключ именно `S`, НЕ `ST`) |
| `E` **или** `EMAILADDRESS` | `email` | как есть |
| `O` | `organization` | как есть |
| `OU` | `bin` | `value.replaceAll("^BIN", "")` |
| `G` | `lastName` | как есть (GIVENNAME → отчество/lastName) |

Всегда в конце: `subjectBuilder.dn(dn)` — исходный DN целиком.

Логика SERIALNUMBER (даёт ИИН или БИН):
```
sn = value(SERIALNUMBER)
if sn.startsWith("BIN"):   bin = value.replaceAll("^BIN", "")   // срезается только префикс BIN
else:                      iin = value.replaceAll("^IIN", "")   // срезается префикс IIN (если есть)
```
- Регэксп `^BIN` / `^IIN` — только якорь начала строки, срезает ровно префикс. Если префикса нет и строка не начинается с `BIN`, всё уходит в `iin` без изменений.
- БИН может прийти двумя путями: из `SERIALNUMBER` с префиксом `BIN`, ИЛИ из `OU` (там всегда `replaceAll("^BIN","")`).

### Подводные камни / отличия от «полного» набора ключей, что был в ТЗ
- **Нет** маппинга для `SN` (как отдельного от SURNAME), `GIVENNAME` (используется только короткий `G`), `ST` (используется только `S`), `BC` (BusinessCategory), `DC`, `O`-как-orgname с доп.логикой. В ЭТОЙ версии NCANode их нет. Если ваш DN отдаёт `ST`/`GIVENNAME`/`OID.2.5.4.x` — LdapName вернёт числовой OID или другой ключ, и поле НЕ заполнится. Учтите при переносе: возможно, вам надо расширить таблицу.
- `X500Principal.toString()` для нестандартных атрибутов выдаёт форму `OID.2.5.4.5=...` или `2.5.4.5=#hex` (DER в hex). NCANode это НЕ разбирает — полагается на то, что Kalkan-provider знает keyword'ы (SERIALNUMBER, SURNAME, G и т.д.). В Go при разборе сырого DER мапьте по числовым OID:
  - CN = `2.5.4.3`, SURNAME = `2.5.4.4`, SERIALNUMBER = `2.5.4.5`, C = `2.5.4.6`, L = `2.5.4.7`, S/ST = `2.5.4.8`, O = `2.5.4.10`, OU = `2.5.4.11`, GIVENNAME(G) = `2.5.4.42`, E/EMAILADDRESS = `1.2.840.113549.1.9.1`.
- Кириллица: значения приходят UTF-8; BouncyCastle/Kalkan декодирует BMPString/UTF8String/PrintableString сам. В Go при разборе DER учтите теги UTF8String(0x0C), PrintableString(0x13), BMPString(0x1E — UTF-16BE).

---

## 2. keyUser (роли) — `getKeyUser` + enum `CertificateKeyUser`

Источник: **Extended Key Usage** (`X509Certificate.getExtendedKeyUsage()` → список OID-строк). Каждый OID мапится через `CertificateKeyUser.fromOID` (точное `equals`), несовпавшие отбрасываются, результат — `Set<CertificateKeyUser>`.

Полная таблица OID → enum (OID НУЦ РК, префикс `1.2.398.3.3.4`):

| OID | enum |
|---|---|
| `1.2.398.3.3.4.1.1` | `INDIVIDUAL` (физлицо) |
| `1.2.398.3.3.4.1.2` | `ORGANIZATION` (юрлицо) |
| `1.2.398.3.3.4.1.2.1` | `CEO` (первый руководитель) |
| `1.2.398.3.3.4.1.2.2` | `CAN_SIGN` (право подписи) |
| `1.2.398.3.3.4.1.2.3` | `CAN_SIGN_FINANCIAL` (право подписи фин. документов) |
| `1.2.398.3.3.4.1.2.4` | `HR` (кадровик) |
| `1.2.398.3.3.4.1.2.5` | `EMPLOYEE` (сотрудник) |
| `1.2.398.3.3.4.2`     | `NCA_PRIVILEGES` |
| `1.2.398.3.3.4.2.1`   | `NCA_ADMIN` |
| `1.2.398.3.3.4.2.2`   | `NCA_MANAGER` |
| `1.2.398.3.3.4.2.3`   | `NCA_OPERATOR` |
| `1.2.398.3.3.4.3`     | `IDENTIFICATION` |
| `1.2.398.3.3.4.3.1`   | `IDENTIFICATION_CON` (очная идентификация) |
| `1.2.398.3.3.4.3.2`   | `IDENTIFICATION_REMOTE` (удалённая) |
| `1.2.398.3.3.4.3.2.1` | `IDENTIFICATION_REMOTE_DIGITAL_ID` |

Замечания:
- Это ровно 15 значений, порядок в enum как выше. Никаких стандартных EKU (serverAuth/clientAuth) в набор не попадает — они просто игнорируются (нет совпадения).
- В Go: читайте extension `2.5.29.37` (extendedKeyUsage), для каждого KeyPurposeId сравнивайте строку OID с таблицей.

---

## 3. gender (`CertificateGender`)

**В этой версии NCANode gender НЕ вычисляется и НЕ заполняется.** Enum `CertificateGender{NONE, MALE, FEMALE}` объявлен, поле `CertificateSubject.gender` существует, но `createCertificateSubjectFromDn` его никогда не устанавливает (builder.gender не вызывается) → в JSON поле отсутствует (`@JsonInclude(NON_NULL)`).

Для вашего Go-сервиса, если пол всё же нужен, стандартная формула из ИИН РК (не из этого кода, но общеизвестная):
- ИИН = 12 цифр: `ГГММДД` + `S` (7-я цифра, век+пол) + порядковый + контрольная.
- 7-я цифра (index 6): нечётная → мужской, чётная → женский. Конкретно: 1,3,5 = MALE (муж., XIX/XX/XXI вв.), 2,4,6 = FEMALE. 0 и др. → NONE.
- В самом NCANode этой логики нет — реализуйте отдельно, если нужно.

---

## 4. keyUsage — `CertificateKeyUsage.fromKeyUsageBits`

Вход: `cert.getKeyUsage()` → `boolean[]` (стандартный порядок бит KeyUsage RFC5280: [0]digitalSignature, [1]nonRepudiation/contentCommitment, [2]keyEncipherment, [3]dataEncipherment, [4]keyAgreement, [5]keyCertSign, [6]cRLSign, [7]encipherOnly, [8]decipherOnly).

Логика (enum `UNKNOWN, AUTH, SIGN`):
```
if bits[0] && bits[1]:  SIGN    // digitalSignature + nonRepudiation → сертификат подписи
elif bits[0] && bits[2]: AUTH   // digitalSignature + keyEncipherment → сертификат аутентификации
else: UNKNOWN
```
- SIGN проверяется ПЕРВЫМ. Если стоят и bit1 и bit2 одновременно — вернётся SIGN.
- В Go: читайте extension `2.5.29.15` (keyUsage, BIT STRING), проверяйте старшие биты (bit0 = MSB первого байта).

---

## 5. Таблицы sign OID → digest OID и hash OID → имя

### `Util.getDigestAlgorithmOidBYSignAlgorithmOid(signOid)` (расширенная, с ГОСТ-2015):
| sign OID | → digest (константа CMSSignedDataGenerator) |
|---|---|
| `1.2.840.113549.1.1.5` (sha1WithRSA) | `DIGEST_SHA1` = `1.3.14.3.2.26` |
| `1.2.840.113549.1.1.11` (sha256WithRSA) | `DIGEST_SHA256` = `2.16.840.1.101.3.4.2.1` |
| `1.2.398.3.10.1.1.2.3.1` (GOST2015-256) | `DIGEST_GOST3411_2015_256` |
| `1.2.398.3.10.1.1.2.3.2` (GOST2015-512) | `DIGEST_GOST3411_2015_512` |
| **иначе (default)** | `DIGEST_GOST34311_95` (старый ГОСТ Р 34.11-94, OID `1.2.398.3.10.1.1.1.1` — kalkan) |

### `KalkanUtil.getDigestAlgorithmOidBYSignAlgorithmOid` (укороченная, БЕЗ ГОСТ-2015):
sha1WithRSA→SHA1, sha256WithRSA→SHA256, иначе→`DIGEST_GOST34311_95`.

### `KalkanUtil.getSignMethodByOID(oid)` → [signAlgURI, hashAlgURI] (XMLDSig namespaces), используется CertificateWrapper для signAlg/hashAlg ID:
| sign OID | ret[0] (sign) | ret[1] (hash) |
|---|---|---|
| `1.2.840.113549.1.1.5` sha1WithRSA | `<MoreAlgo>rsa-sha1` | `<MoreAlgo>sha1` |
| `1.2.840.113549.1.1.11` sha256WithRSA | `<MoreAlgo>rsa-sha256` | `XMLCipherParameters.SHA256` |
| `1.2.398.3.10.1.1.2.3.2` GOST3410-2015-512 | `urn:...:gostr34102015-gostr34112015-512` | `urn:...:gostr34112015-512` |
| `1.2.398.3.10.1.1.2.3.1` GOST3410-2015-256 | `urn:...:gostr34102015-gostr34112015-256` | `urn:...:gostr34112015-256` |
| иначе (default, старый ГОСТ) | `<MoreAlgo>gost34310-gost34311` | `<MoreAlgo>gost34311` |

(`<MoreAlgo>` = `Constants.MoreAlgorithmsSpecNS` = `http://www.w3.org/2001/04/xmldsig-more#`. urn-префикс ГОСТ-2015 = `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:`.)

### `KalkanUtil.getHashingAlgorithmByOID(oid)` — hash OID → имя (для TSP):
| OID (TSPAlgorithms) | имя |
|---|---|
| MD5 `1.2.840.113549.2.5` | `MD5` |
| SHA1 `1.3.14.3.2.26` | `SHA1` |
| SHA224 `2.16.840.1.101.3.4.2.4` | `SHA224` |
| SHA256 `2.16.840.1.101.3.4.2.1` | `SHA256` |
| SHA384 `2.16.840.1.101.3.4.2.2` | `SHA384` |
| SHA512 `2.16.840.1.101.3.4.2.3` | `SHA512` |
| RIPEMD128 `1.3.36.3.2.2` | `RIPEMD128` |
| RIPEMD160 `1.3.36.3.2.1` | `RIPEMD160` |
| RIPEMD256 `1.3.36.3.2.3` | `RIPEMD256` |
| GOST34311GT `1.2.398.3.10.1.1.1.1` (kalkan вариант) | `GOST34311GT` |
| GOST34311 `1.2.398.3.10.1.1.1` | `GOST34311` |

(OID-значения TSPAlgorithms — стандартные; kalkan-специфичные ГОСТ-OID из пакета `kz.gov.pki.kalkan`. `getHashingAlgorithmByOID` возвращает `null`, если OID не в таблице.)

Также: в CertificateInfo кладётся `signAlg = cert.getSigAlgName()` (человекочитаемое имя из провайдера, напр. `SHA256withRSA` / `GOST3411withGOST3410-2015-256`), а НЕ OID.

---

## 6. Все поля DTO (имена + типы)

### `CertificateInfo` (`@JsonInclude(NON_NULL)`, собирается билдером в `toCertificateInfo`)
| поле | тип | источник |
|---|---|---|
| `valid` | boolean | `isValid(date, checkOcsp, checkCrl)` |
| `revocations` | `List<CertificateRevocationStatus>` | из crlStatus + ocspStatus |
| `notBefore` | `Date` | `cert.getNotBefore()` |
| `notAfter` | `Date` | `cert.getNotAfter()` |
| `keyUsage` | `CertificateKeyUsage` (enum) | `fromKeyUsageBits` |
| `serialNumber` | `String` | `cert.getSerialNumber().toString(16)` — **hex, БЕЗ ведущих нулей, нижний регистр, знаковый** (BigInteger) |
| `signAlg` | `String` | `cert.getSigAlgName()` |
| `keyUser` | `Set<CertificateKeyUser>` | EKU-роли |
| `publicKey` | `String` | Base64(`publicKey.getEncoded()`) — DER SubjectPublicKeyInfo |
| `signature` | `String` | Base64(`cert.getSignature()`) |
| `subject` | `CertificateSubject` | из subject DN |
| `issuer` | `CertificateSubject` | из issuer DN |

### `CertificateSubject` (`@JsonInclude(NON_NULL)`)
`commonName:String`, `lastName:String` (из G), `surName:String` (из SURNAME), `email:String`, `organization:String`, `gender:CertificateGender` (**всегда null в этой версии**), `iin:String`, `bin:String`, `country:String`, `locality:String`, `state:String`, `dn:String`.

### `CertificateRevocationStatus`
`revoked:boolean`, `by:CertificateRevocation` (enum OCSP|CRL), `revocationTime:Date`, `reason:String`.
- Из CRL: `revoked = (result==REVOKED)`, `revocationTime = revocationDate`, `by=CRL`, `reason=reason`.
- Из OCSP: `revoked = (result==REVOKED)`, `revocationTime`, `by=OCSP`, `reason = message`.

### Прочие enum
- `CertificateKeyUsage`: UNKNOWN, AUTH, SIGN.
- `CertificateKeyUser`: 15 значений (см. §2).
- `CertificateGender`: NONE, MALE, FEMALE.
- `CertificateRevocation`: OCSP, CRL.

---

## 7. isValid / attachValidationData

### `attachValidationData(cert, checkOcsp, checkCrl)` (CertificateService)
```
cert.issuerCertificate = caService.getRootCertificateFor(cert).orElse(null)
cert.ocspStatus = checkOcsp ? ocspService.verify(cert, cert.issuerCertificate) : null
cert.crlStatus  = checkCrl  ? crlService.verify(cert) : null
```

### `getRootCertificateFor(cert)` (CaService) — откуда берётся issuer-серт
1. Если `issuerDN == subjectDN` (самоподписанный) → `Optional.empty()`.
2. Иначе среди кэшированных корневых сертификатов НУЦ (скачиваются по `NCANODE_CA_URL`, лежат в кэш-каталоге `ca/*.cer`) ищется первый, у которого `root.subjectX500Principal == cert.issuerX500Principal` **И** `cert.verify(root.getPublicKey())` (криптопроверка подписи проходит).
- Сравнение issuer/subject — по `X500Principal.equals` (нормализованное сравнение DN).

### `isValid(date, checkOcsp, checkCrl)` (CertificateWrapper) — все условия по И:
```
isDateValid(date)                                   // date в (notBefore, notAfter), СТРОГО after/before
&& issuerCertificate != null                        // issuer найден и подпись верна
&& issuerCertificate.isDateValid(date)              // issuer тоже действителен по датам
&& (!checkOcsp || (ocspStatus != null && ВСЕ ocspStatus.isActive()))
&& (!checkCrl  || (crlStatus  != null && crlStatus.result == ACTIVE))
```
- `isDateValid`: `date.after(notBefore) && date.before(notAfter)` — границы НЕ включаются (строгое сравнение).
- Если OCSP/CRL не запрошены — соответствующее условие всегда true.
- Если issuer не найден в кэше НУЦ → сертификат считается НЕвалидным (issuerCertificate == null). То есть валидность завязана на наличие и актуальность корневых сертификатов НУЦ в кэше.
- OCSP: valid требует чтобы ВСЕ ответы были ACTIVE (`allMatch(isActive)`). CRL: `result == ACTIVE`.

---

## 8. Подводные камни / особенности

1. **serialNumber** = `BigInteger.toString(16)` — знаковый, без ведущих нулей, lower-case hex. В Go, если серийник берёте из DER как беззнаковые байты, приведите к тому же виду (без ведущего 0, нижний регистр), иначе не совпадёт с NCANode. Для отрицательного старшего бита BigInteger дал бы знак `-` — на практике серийники положительные.
2. **DN парсится из строки RFC2253** (`X500Principal.toString`), а не из DER. Порядок RDN в строке — обратный DER. Для вашего DER-парсера семантика та же, но следите за multi-valued RDN (`a=b+c=d`) — LdapName разбивает их корректно, ваш парсер тоже должен.
3. **Сравнение ключей RDN — регистронезависимое** (`equalsIgnoreCase`). `email` ловится и как `E`, и как `EMAILADDRESS`.
4. **`state` мапится только с ключа `S`**, не `ST`. При разборе DER (OID 2.5.4.8) кладите в state.
5. **gender не реализован** — не тратьте время на воспроизведение; при необходимости считайте из 7-й цифры ИИН сами.
6. **keyUser** = только из ExtendedKeyUsage (2.5.29.37); стандартные EKU игнорируются.
7. **Провайдер Kalkan обязателен** для чтения ГОСТ-сертификатов (`CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)`). Ваш нативный C-API Kalkan решает ту же задачу; таблицы OID выше — провайдеро-независимы.
8. **ГОСТ-2015 OID подписи**: 256 = `1.2.398.3.10.1.1.2.3.1`, 512 = `1.2.398.3.10.1.1.2.3.2`. Старый ГОСТ идёт как default-ветка.
9. **verify (подпись данных)** в CertificateService использует `Signature.getInstance(x509.getSigAlgName())` + `initVerify(publicKey)`; данные берутся `data.getBytes(UTF_8)`, подпись — Base64. Не относится к разбору серта, но показывает, что имя алгоритма = `getSigAlgName()`.
10. **valid=false когда issuer не в кэше НУЦ** — важное поведенческое отличие: без загруженных корневых сертификатов ЛЮБОЙ сертификат невалиден. Если ваш Go-сервис не тянет CA-кэш, вам нужен свой источник доверенных корней НУЦ РК.
11. Base64 входного сертификата чистится `replaceAll("\\s","")` перед декодом.


---

# Раздел 2 — CMS и TSP

## NCANode: CMS + TSP — извлечение для воспроизведения в Go поверх нативного Kalkan C-API

Источники:
- `service/CmsService.java`, `service/TspService.java`
- `util/KalkanUtil.java`, `util/Util.java`
- `dto/tsp/{TspInfo,TsaPolicy}.java`, `dto/cms/CmsSignerInfo.java`
- `dto/request/{CmsCreateRequest,CmsVerifyRequest,SignerRequest}.java`
- `dto/response/{CmsResponse,CmsVerificationResponse,CmsDataResponse}.java`
- OID-значения политик TSA извлечены дизассемблированием `kz/gov/pki/kalkan/asn1/knca/KNCAObjectIdentifiers.class` (из `knca_provider_jce_kalkan-0.7.5.jar`).

Всё в NCANode работает через Java-обёртку Kalkan (`CMSSignedDataGenerator`, `CMSSignedData`, `SignerInformation`, `TimeStampToken`).
В нашем Go-сервисе те же шаги надо собрать из `SignData`/`VerifyData`/`KC_GetCertFromCMS`/`KC_GetTimeFromSig` + ручной разбор ASN.1.

---

## 1. CMS: sign / sign-add / verify / extract

### 1.1 Общие правила I/O
- `data` (контент) и `cms` — всегда **base64** на входе и выходе.
- `cms` в ответе = base64(DER всего SignedData).
- attached vs detached задаётся флагом `detached`:
  - в Java: `generator.generate(cmsData, includeContent, provider)`, где `includeContent = !detached`.
  - attached (`detached=false`) → контент вкладывается в `SignedData.encapContentInfo.eContent`.
  - detached (`detached=true`) → `eContent` отсутствует, при verify контент передаётся отдельно.

### 1.2 CREATE (создание нового подписанного CMS) — `CmsService.create`
Пошагово:
1. `data = base64decode(request.data)`.
2. Создать `CMSSignedDataGenerator`, обёрнуть данные в `CMSProcessableByteArray(data)`.
3. Для каждого `SignerRequest` (метод `addSignersToCmsGenerator`):
   - прочитать key store (PKCS12): достать `privateKey` и сертификат `X509Certificate`;
   - (Java делает демонстрационный `Signature.getInstance(cert.getSigAlgName()).initSign/update` — фактически на подпись не влияет, реальную подпись делает generator);
   - `generator.addSigner(privateKey, cert, digestOid)`, где
     `digestOid = Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getSigAlgOID())` (см. §3);
   - добавить `cert` в список `certificates` (порядок важен — используется дальше для TSP по индексу).
4. Собрать `CertStore` (Collection) из `certificates` и `generator.addCertificatesAndCRLs(chainStore)` — сертификаты подписантов кладутся внутрь CMS.
5. `signed = generator.generate(cmsData, !detached, provider)`.
6. Если `withTsp=true` — добавить TSP к каждому подписанту (см. §2), затем
   `signed = CMSSignedData.replaceSigners(signed, newSigners)`.
7. Вернуть `base64(signed.getEncoded())`.

Порядок соответствия «подписант ↔ сертификат»: signers из `signed.getSignerInfos().getSigners()` перебираются в том же порядке, что и список `certificates` (индекс `i++`). Для Go важно сохранять тот же порядок cert’ов, что и signerInfos.

### 1.3 ADD SIGNERS (co-sign, добавление подписи в существующий CMS) — `CmsService.addSigners`
1. Требуется непустой `request.cms`, иначе `ClientException("CMS argument not specified")`.
2. `decodedCms = base64decode(cms)`; `cms = new CMSSignedData(decodedCms)`.
3. Восстановить контент:
   - если `cms.getSignedContent() == null` (**detached**): нужен `request.data`, иначе
     `ClientException("Data must be specifieed for detached CMS")`. Тогда
     `cms = new CMSSignedData(new CMSProcessableByteArray(decodedData), decodedCms)`.
   - иначе (**attached**): извлечь контент `cms.getSignedContent().write(out)` → `decodedData`.
4. Новый `generator`; `generator.addSigners(cms.getSignerInfos())` — переносим СТАРЫЕ подписи.
5. `certificates = getCertificatesFromCmsSignedData(cms)` — вытащить существующие сертификаты подписантов из CMS (по `signer.getSID()` через certStore).
6. `addSignersToCmsGenerator(generator, decodedData, certificates, request.signers)` — добавить новых подписантов (в конец списка `certificates`).
7. `CertStore` строится из **уникальных** cert’ов: `certificates.stream().distinct()` — дедуп, чтобы при повторной подписи одинаковые cert’ы не дублировались в CMS.
8. `signed = generator.generate(cmsData, !detached, provider)`.
9. Если `withTsp=true`:
   - перебор signerInfos c индексом `i`, `cert = certificates.get(i)`;
   - **НЕ перезатирать TSP у старых подписантов**: если `isSignerSameAsPrevious(signer, cms)` (SID совпал с одним из уже существовавших в исходном `cms`) → добавить signer как есть, без нового TSP;
   - иначе → `tspService.addTspToSigner(signer, cert, policy)`.
   - `dedup/сравнение по SID`: `SignerInformation.getSID().equals(...)` (IssuerAndSerialNumber / SubjectKeyIdentifier).
10. Вернуть `base64(signed.getEncoded())`.

Важный нюанс для Go: при co-sign старые signerInfos и их unsignedAttrs (в т.ч. уже существующие TSP-токены) сохраняются нетронутыми; новый TSP ставится только новым подписантам.

### 1.4 VERIFY — `CmsService.verify(signedCms, detachedData, checkOcsp, checkCrl)`
1. `cms = new CMSSignedData(base64decode(signedCms))`.
2. Если `detachedData != null` И `cms.getSignedContent() == null` (detached) → пересоздать
   `cms = new CMSSignedData(new CMSProcessableByteArray(base64decode(detachedData)), base64decode(signedCms))`.
3. `certStore = cms.getCertificatesAndCRLs(...)`.
4. `valid = true`. Перебор всех `signerInfos`:
   - по `signer.getSID()` найти сертификат(ы) в certStore;
   - для каждого cert: подтянуть OCSP/CRL (`attachValidationData`), затем
     `signer.verify(cert.getPublicKey(), provider)` (проверка криптоподписи) И
     `cert.isValid(currentDate, checkOcsp, checkCrl)` (срок/цепочка/отзыв);
   - если хоть одна проверка `false` → `valid = false` (общий флаг на весь CMS);
   - собрать `CertificateInfo` в signerInfo.
   - **TSP при verify**: см. §2.4.
5. Ответ: `CmsVerificationResponse{ valid, signers[] }`, каждый signer = `CmsSignerInfo{ certificates[], tsp }`.

Замечание: `valid` — единый по всему CMS (AND по всем подписантам и всем cert’ам). В Go при нескольких подписантах лучше хранить и по-signer статус, но семантику NCANode повторяем как общий AND.

### 1.5 EXTRACT — `CmsService.extract(signedCms)`
1. `cms = new CMSSignedData(base64decode(signedCms))`.
2. Если `cms.getSignedContent() == null` → `ClientException("CMS doesn't have signed content")` (нельзя извлечь из detached).
3. Иначе `cms.getSignedContent().write(out)` → вернуть `base64(out)` как `data`.

---

## 2. TSP (метки времени)

### 2.1 Policy ID (enum `TsaPolicy` → `KNCAObjectIdentifiers`)
Базовый OID политики TSA: **`1.2.398.3.3.2.6`** (`tsa_policy_id`), политики — его дети:

| enum                  | поле Kalkan            | OID                     | назначение            |
|-----------------------|------------------------|-------------------------|-----------------------|
| `TSA_GOST_POLICY`     | `tsa_gost_policy`      | `1.2.398.3.3.2.6.1`     | GOST 34.311-95        |
| (нет в enum) RSA      | `tsa_rsa_policy`       | `1.2.398.3.3.2.6.2`     | RSA (SHA)             |
| `TSA_GOSTGT_POLICY`   | `tsa_gostgt_policy`    | `1.2.398.3.3.2.6.3`     | GOST GT               |
| `TSA_GOST2015_POLICY` | `tsa_gost2015_policy`  | `1.2.398.3.3.2.6.4`     | GOST 34.311-2015      |

**Политика по умолчанию** (если `tsaPolicy` не передан): `TSA_GOST2015_POLICY` = `1.2.398.3.3.2.6.4`.
(Значения OID получены дизассемблированием `KNCAObjectIdentifiers.class`; enum отдаёт `.getPolicyId()` = строку OID.)

### 2.2 Построение TSP-запроса — `TspService.create(data, hashAlg, reqPolicy)`
Ключевой момент: **TSP считается не от контента, а от подписи подписанта** —
`create(signer.getSignature(), hashAlg, policy)` (в `addTspToSigner`). `signer.getSignature()` = байты значения подписи (`SignatureValue`) данного signerInfo.

Шаги:
1. `md = MessageDigest.getInstance(hashAlg, provider); hash = md.digest(data)` — хэш от переданных байт (= от signature подписанта).
2. `TimeStampRequestGenerator reqGen; reqGen.setCertReq(true); reqGen.setReqPolicy(reqPolicy)`.
3. `request = reqGen.generate(hashAlg, hash, nonce)`, где
   `nonce = BigInteger.valueOf(System.currentTimeMillis())`.
4. HTTP POST на `ncanode.tsp.url`:
   - заголовок `Content-Type: application/timestamp-query`;
   - тело = `request.getEncoded()` (DER TimeStampReq);
   - ожидается HTTP 200, иначе `TspException`.
5. `response = new TimeStampResponse(body); response.validate(request)` (проверка соответствия nonce/imprint) → `response.getTimeStampToken()`.
6. Ретраи: `max(1, ncanode.tsp.retries)` попыток; при исключении повтор, в конце пробрасывается последнее.

`hashAlg` для запроса выбирается по алгоритму подписи cert’а —
`KalkanUtil.getTspHashAlgorithmByOid(cert.getSigAlgOID())` (см. §3).

### 2.3 Вставка токена как unsigned attribute — `TspService.addTspToSigner`
1. Взять текущие `unsignedAttributes` подписанта (может быть null → пустой вектор).
2. `tsp = create(signer.getSignature(), tspHashAlg, policy)`; `ts = tsp.getEncoded()` (DER TimeStampToken = ContentInfo/SignedData).
3. Обернуть в атрибут:
   `Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(Util.byteToASN1(ts)))`.
   - OID `id_aa_signatureTimeStampToken` = **`1.2.840.113549.1.9.16.2.14`**.
   - значение атрибута = сам DER-токен, распарсенный как ASN.1 объект, завёрнутый в `DERSet` (SET OF).
4. Добавить атрибут в вектор и
   `SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(vector))`.

Т.е. в структуре: `signerInfo.unsignedAttrs += Attribute{ attrType=1.2.840.113549.1.9.16.2.14, attrValues=SET{ TimeStampToken } }`.
Для Go поверх C-API: TSP-токен — это результат обращения к TSA по значению подписи; его надо DER-встроить как unsigned attribute с этим OID (в C-API часто есть отдельная функция добавления TSP; иначе — ручная модификация ASN.1 signerInfo).

### 2.4 Извлечение полей TSP при verify — `CmsService.verify` + `TspService.info`
1. Взять `signer.getUnsignedAttributes()`; искать ключ `id_aa_signatureTimeStampToken` (`1.2.840.113549.1.9.16.2.14`).
2. Значение может быть `Vector` (тогда берётся `.get(0)`) или одиночный `Attribute`.
3. `attr.getAttrValues().size()` должен быть == 1, иначе ошибка `"Too many TSP tokens"`.
4. Из значения атрибута собрать `CMSSignedData tspCms = new CMSSignedData(attrValue.getDERObject().getEncoded())`.
5. `TspService.info(tspCms)`:
   - `tspt = new TimeStampToken(tspCms)`;
   - найти cert TSA по `tspt.getSID()` в `tspCms.getCertificatesAndCRLs(...)`;
   - если cert нет → `Optional.empty()`;
   - `tspt.validate(cert, provider)` (проверка подписи токена и imprint);
   - вернуть `tspt.getTimeStampInfo()` (`TimeStampTokenInfo`).
6. Поля `TspInfo` из `TimeStampTokenInfo`:
   - `serialNumber` = hex(`tspi.getSerialNumber().toByteArray()`) — HEX-строка;
   - `genTime`     = `tspi.getGenTime()` (Date, момент штампа);
   - `policy`      = `tspi.getPolicy()` (OID-строка политики TSA);
   - `tsa`         = `tspi.getTsa()?.toString()` (может быть null → null);
   - `tspHashAlgorithm` = `KalkanUtil.getHashingAlgorithmByOID(tspi.getMessageImprintAlgOID())`
     (маппинг OID→имя: MD5/SHA1/SHA224/SHA256/SHA384/SHA512/RIPEMD*/GOST34311/GOST34311GT);
   - `hash`        = hex(`tspi.getMessageImprintDigest()`) — HEX imprint (хэш подписи).
7. Ошибки при разборе TSP не валят verify: логируются как warn, tsp остаётся null.

Соответствие нашему `KC_GetTimeFromSig`: он отдаёт genTime; остальные поля (serialNumber, policy, tsa, algo, imprint) в Go придётся доставать разбором ASN.1 TimeStampToken → TSTInfo (SEQUENCE: version, policy(OID), messageImprint{algId, hashedMessage}, serialNumber(INTEGER), genTime(GeneralizedTime), опц. tsa[GeneralName]).

---

## 3. Выбор digest / hash-алгоритма по signAlg сертификата

По `cert.getSigAlgOID()`:

**Для digest подписи CMS** — `Util.getDigestAlgorithmOidBYSignAlgorithmOid(signOid)` (версия из `Util.java`, используется в CmsService):
| signOid                          | что за алгоритм подписи | digest (CMSSignedDataGenerator.*) |
|----------------------------------|-------------------------|-----------------------------------|
| `sha1WithRSAEncryption`          | RSA-SHA1                | `DIGEST_SHA1`                     |
| `sha256WithRSAEncryption`        | RSA-SHA256              | `DIGEST_SHA256`                   |
| `1.2.398.3.10.1.1.2.3.1`         | GOST3410-2015-256       | `DIGEST_GOST3411_2015_256`        |
| `1.2.398.3.10.1.1.2.3.2`         | GOST3410-2015-512       | `DIGEST_GOST3411_2015_512`        |
| иначе (старый GOST 34310)        | —                       | `DIGEST_GOST34311_95`             |

(Есть также урезанная версия в `KalkanUtil` без GOST-2015 — в CMS не используется, только не путать.)

**Для hash TSP-запроса** — `KalkanUtil.getTspHashAlgorithmByOid(signOid)` → `TSPAlgorithms.*`:
| signOid                   | TSP hashAlg                |
|---------------------------|---------------------------|
| `sha1WithRSAEncryption`   | `TSPAlgorithms.SHA1`      |
| `sha256WithRSAEncryption` | `TSPAlgorithms.SHA256`    |
| иначе (любой GOST)        | `TSPAlgorithms.GOST34311` |

Важно: для GOST-2015 сертификатов digest CMS = GOST3411-2015, но hash TSP-запроса всё равно = `GOST34311` (старый) — в NCANode нет отдельной ветки GOST2015 для TSP. Учесть при воспроизведении.

Константы OID GOST-2015 (из `KalkanUtil`): `GOST3410_256_2015 = 1.2.398.3.10.1.1.2.3.1`, `GOST3410_512_2015 = 1.2.398.3.10.1.1.2.3.2`.

---

## 4. Поля request / response DTO

### CmsCreateRequest (используется и для create, и для addSigners)
- `cms`: String (base64) — исходный CMS, только для addSigners; для create игнорируется.
- `data`: String (base64) — контент; обязателен для create и для detached addSigners.
- `signers`: List<SignerRequest> — **@NotEmpty**.
- `withTsp`: boolean, default **false**.
- `tsaPolicy`: enum `TsaPolicy` (`TSA_GOST2015_POLICY|TSA_GOST_POLICY|TSA_GOSTGT_POLICY`), nullable → default GOST2015.
- `detached`: boolean, default **false**.

### SignerRequest
- `key`: String — **@NotEmpty**, base64 PKCS12 (P12/PFX) ключевого контейнера.
- `password`: String — **@NotEmpty**, пароль контейнера.
- `keyAlias`: String — nullable, алиас ключа в контейнере (если несколько).
- `referenceUri`: String — nullable (используется в XML-подписи, не в CMS).

### CmsVerifyRequest (extends VerifyRequest)
- `cms`: String — **@NotEmpty**, base64 подписанного CMS.
- `data`: String — nullable, base64 контента для detached-проверки.
- из базового `VerifyRequest`: параметры проверки отзыва — `revocationCheck` (список: OCSP/CRL). В `CmsService.verify` разворачивается в `checkOcsp` и `checkCrl` (boolean). (Сам список — в VerifyRequest, не в этом файле.)

### Response DTO (все extends StatusResponse → есть `status`, `message`)
- `CmsResponse`: `cms` (String, base64 результата).
- `CmsDataResponse`: `data` (String, base64 извлечённого контента).
- `CmsVerificationResponse`: `valid` (boolean), `signers` (List<CmsSignerInfo>).
- `CmsSignerInfo`: `certificates` (List<CertificateInfo>), `tsp` (TspInfo|null).
- `TspInfo`: `serialNumber`(hex), `genTime`(Date), `policy`(OID), `tsa`(String|null), `tspHashAlgorithm`(имя), `hash`(hex imprint).

---

## 5. Нюансы (для корректного Go-порта)

1. **TSP считается от `signer.getSignature()` (значение подписи), а НЕ от контента.** Это критично: imprint в TSP = хэш байтов SignatureValue конкретного signerInfo.
2. **Не перезатирать TSP у старых подписантов** при co-sign: сравнение по `SID` (`isSignerSameAsPrevious`); старым signerInfo unsignedAttrs не трогаем, новый TSP только новым.
3. **Detached без данных** → ошибки: addSigners `"Data must be specifieed for detached CMS"`, extract `"CMS doesn't have signed content"`. verify для detached требует `data` + пересборку CMSSignedData с внешним контентом.
4. **Дедуп сертификатов**: в addSigners CertStore строится из `distinct()` cert’ов (при повторной подписи тем же cert не плодим дубликаты), НО список `certificates` для сопоставления по индексу с signerInfos — БЕЗ дедупа (порядок 1:1 с signers).
5. **Порядок cert ↔ signerInfo**: строго по индексу `i++`. В Go держать те же инварианты порядка при добавлении подписантов и при навешивании TSP.
6. **Кодировки**: везде base64 для cms/data/key; serialNumber и hash в TspInfo — HEX (нижний регистр, из `Hex.encode`); genTime — Date (в TSTInfo это GeneralizedTime, UTC).
7. **nonce TSP** = `System.currentTimeMillis()` (не крипто-стойкий, но так в NCANode); `certReq=true` (просим cert TSA в токене).
8. **`response.validate(request)`** обязательна — проверяет соответствие ответа запросу (nonce, imprint, policy). При verify — `tspt.validate(cert)` проверяет подпись токена.
9. **valid при verify** — единый AND по всем подписантам и всем их cert’ам; ошибка TSP не влияет на valid (только warn).
10. **TimeStampToken по структуре — это CMS SignedData** (ContentInfo с eContentType=id-ct-TSTInfo). Разбирается как `new CMSSignedData(...)` / `new TimeStampToken(...)`. Для Go: парсить как вложенный CMS, внутри eContent = DER TSTInfo.


---

# Раздел 3 — XML / WSSE / ключи

## NCANode: XML / WSSE подпись и работа с ключами (для Go + native Kalkan C-API)

Источник: NCANode (Java, Spring). Ниже — извлечённая логика для воспроизведения в нашем
Go-сервисе (SignXML / VerifyXML / SignWSSE / KC_LoadKeyStore) поверх нативного Kalkan C-API.

---

## 0. Инициализация криптостека (однократно, при старте)

`KalkanConfiguration.kalkanProvider()`:
1. `new KalkanProvider()` — создать провайдер KalkanCrypt.
2. `Security.addProvider(kalkanProvider)` — зарегистрировать в JCE.
3. `KncaXS.loadXMLSecurity()` — регистрирует ГОСТ-алгоритмы (URI ↔ реализация) в Apache
   Santuario (org.apache.xml.security). Без этого вызова XMLDSIG не знает про gost-URI.

Аналог для Go/native: убедиться, что при инициализации Kalkan C-API загружены и провайдер,
и «xmldsig»-часть, регистрирующая ГОСТ-URI. Наша обвязка XML-подписи должна уметь
резолвить эти URI в native-хэш/подпись сами (Santuario у нас нет — мы формируем XML руками).

---

## 1. XML SIGN (XMLDSIG, enveloped)

Точка входа: `XmlService.sign(XmlSignRequest)`.

### 1.1 Чтение и предобработка документа
- `DocumentWrapper(xml)`: DOM-парсер с `setNamespaceAware(true)`, XInclude off,
  ExpandEntityReferences off, FEATURE_SECURE_PROCESSING on, отключены external DTD/entities.
  **Namespace-aware обязателен** (иначе C14N и id-резолвинг сломаются).
- Перед парсингом строка `xml.trim()`, кодировка **UTF-8** жёстко.
- `clearSignatures` (флаг запроса): если true — до подписи удаляются существующие
  `ds:Signature` из корня (`root.getElementsByTagName("ds:Signature")` + removeChild).
  ВНИМАНИЕ на баг оригинала: удаляют по live-NodeList в цикле по индексу — на практике при
  наличии enveloped-подписей срабатывает не идеально, но нам важно поведение: «очистить старые».
- `trimXml` (флаг): `removeWhitespace(document)` — удаляет ВСЕ text-ноды, состоящие только из
  пробелов/переводов строк (обход DocumentTraversal SHOW_TEXT). Делать это ДО подписи, т.к.
  меняет канонизированную форму.

### 1.2 Множественная подпись
- `kalkanWrapper.read(signers)` возвращает список keystore (по одному на signer).
- Цикл: для каждого signer вызывается `document.createXmlSignature(cert, referenceUri).sign(privateKey)`.
- Каждая новая `ds:Signature` **appendChild в корневой элемент документа** (enveloped, все
  подписи — прямые дети корня). Подписи добавляются последовательно; каждая последующая
  подпись охватывает документ уже с ранее добавленными подписями (порядок важен → на verify
  снимаются в обратном порядке, см. п.2).
- У каждого signer свой `referenceUri` (из `SignerRequest.referenceUri`).

### 1.3 Создание одной подписи — `DocumentWrapper.createXmlSignature(cert, referenceUri)`
1. `new XMLSignature(document, "", signAlgorithmId)` — baseURI пустой, алгоритм подписи из серта.
2. `document.getDocumentElement().appendChild(signature.getElement())` — вставка в корень.
3. Transforms (порядок ВАЖЕН, именно такой):
   - `Transforms.TRANSFORM_ENVELOPED_SIGNATURE`
     (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`)
   - `XMLCipherParameters.N14C_XML_CMMNTS` =
     `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`
     (эксклюзивная НЕ используется здесь — обычный C14N with comments).
4. `addDocument(referenceUri==null?"":referenceUri, transforms, hashAlgorithmId)` —
   Reference URI = "" (весь документ) если не задан, иначе строка как есть (обычно `#id`).
5. `addKeyInfo(x509Certificate)` — в KeyInfo кладётся **X509Certificate (X509Data/X509Certificate)**.
6. `sign(privateKey)` — вычисление.

### 1.4 Выбор алгоритмов по OID сертификата — `KalkanUtil.getSignMethodByOID(sigAlgOID)`
Возвращает пару [signatureMethodURI, digestMethodURI]. OID берётся из
`x509Certificate.getSigAlgOID()`. Маппинг:

| OID сертификата | SignatureMethod URI | DigestMethod URI |
|---|---|---|
| sha1WithRSA (1.2.840.113549.1.1.5) | `...xmldsig-more#rsa-sha1` | `...xmldsig-more#sha1` |
| sha256WithRSA (1.2.840.113549.1.1.11) | `...xmldsig-more#rsa-sha256` | `http://www.w3.org/2001/04/xmlenc#sha256` |
| GOST3410-2015-512 `1.2.398.3.10.1.1.2.3.2` | `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512` | `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512` |
| GOST3410-2015-256 `1.2.398.3.10.1.1.2.3.1` | `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256` | `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256` |
| всё остальное (старый ГОСТ 34.310/34.311) | `...xmldsig-more#gost34310-gost34311` | `...xmldsig-more#gost34311` |

Где `...xmldsig-more` = `Constants.MoreAlgorithmsSpecNS` =
`http://www.w3.org/2001/04/xmldsig-more#`.
(«default»-ветка = старые ГОСТ-сертификаты 2004 — большинство legacy-ключей РК.)

Для Go: определить sigAlgOID сертификата через native-парсинг, выбрать URI по этой же
таблице и подставить в `<SignatureMethod Algorithm=...>` / `<DigestMethod Algorithm=...>`.

### 1.5 Наблюдения по префиксам/namespace
- Весь код Santuario пишет `ds:` префикс для XMLDSIG namespace
  `http://www.w3.org/2000/09/xmldsig#`. На verify поиск идёт строго по `getElementsByTagName("ds:Signature")`
  — т.е. NCANode ожидает именно префикс `ds`. Наш генератор XML должен использовать `ds:`.

Примечание про `signNodeId/parentSignNode/parentNameSpace`: в ЭТОЙ версии исходников (v3,
Spring) таких параметров в XmlSignRequest/SignerRequest НЕТ. Есть только `referenceUri`
на signer + `clearSignatures`/`trimXml` на запрос. Логика «подписать конкретный узел по id»
реализуется через `referenceUri = "#<id>"`. (Параметры signNodeId/parentSignNode —
из старого NCANode v1; здесь заменены на referenceUri + всегда appendChild в корень.)

---

## 2. XML VERIFY — `XmlService.verify(xml, checkOcsp, checkCrl)`

1. Парс документа (removeSignatures=false).
2. `signatures = root.getElementsByTagName("ds:Signature")`; кол-во = signaturesLength.
3. Цикл `signaturesLength` раз, но КАЖДУЮ итерацию берётся **последняя** подпись
   `signatures.item(getLength()-1)` и после проверки `root.removeChild(signature)`.
   → подписи снимаются и проверяются в ОБРАТНОМ порядке добавления (LIFO). Это критично для
   enveloped-множественной подписи: внешняя (добавленная последней) охватывает внутренние,
   поэтому её надо проверять первой и удалять, чтобы обнажить документ для следующей.
4. Для каждой: `XMLSignatureWrapper(signatureElement)` → `new XMLSignature(el, "")`.
5. Сертификат: `xmlSignature.getKeyInfo().getX509Certificate()` (из KeyInfo/X509Data).
   Если серта нет — valid=false, в signers добавляется null, continue.
6. `certificateService.attachValidationData(cert, ocsp, crl)` — цепочка/issuer/OCSP/CRL.
7. Валидна если `xmlSignature.checkSignatureValue(cert)` И `cert.isValid(now, ocsp, crl)`.
   `check()` внутри = `checkSignatureValue(getX509Certificate())` — проверка по открытому ключу
   из KeyInfo самого документа.
8. `signers[]` = список CertificateInfo по каждому серту (subject/issuer/serial/validity/keyUsage/
   IIN/BIN из DN и т.д. — см. CertificateWrapper.toCertificateInfo).
9. Если подписей 0 → valid=false.

Для Go VerifyXML: найти все `ds:Signature`, для каждой извлечь X509 из
`KeyInfo/X509Data/X509Certificate`, проверить SignatureValue нативно по алгоритму из серта,
плюс валидировать сам сертификат. Порядок обхода — LIFO для enveloped.

---

## 3. WSSE (SOAP) — `WsseService.sign(WsseSignRequest)`

Отличия от обычного XML: подпись живёт в SOAP Security-заголовке, ссылается на Body по wsu:Id,
сертификат передаётся через SecurityTokenReference (KeyIdentifier), а не X509Data.

### Запрос
`WsseSignRequest`: `xml`, `key`(base64 p12), `password`, `keyAlias`(nullable), `trimXml`.
**Только ОДИН ключ** (не список) — WSSE подписывает одной подписью.

### Шаги
1. Прочитать keystore: `kalkanWrapper.read(key, keyAlias, password)` → cert + privateKey.
2. `xmlService.prepare(xml, trimXml).trim()` → байты UTF-8 → `MessageFactory.createMessage`
   (SAAJ SOAP). Получить Envelope/Body/Header.
3. Присвоить Body атрибут `wsu:Id = "id-" + UUID` в namespace
   `WSConstants.WSU_NS = http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd`,
   префикс `wsu`.
4. Если Header нет — `env.addHeader()`.
5. Transforms для reference: **только** `TRANSFORM_C14N_EXCL_OMIT_COMMENTS`
   (`http://www.w3.org/2001/10/xml-exc-c14n#`) — эксклюзивная C14N БЕЗ комментариев.
   (в отличие от обычного XML, где enveloped + C14N-with-comments!)
6. `XMLSignatureWrapper(doc, cert.signAlgorithmId, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)`
   — конструктор, где вручную создаются SignatureMethod и CanonicalizationMethod элементы:
   SignedInfo/CanonicalizationMethod = exclusive-c14n.
7. `addDocument("#"+bodyId, transforms, cert.hashAlgorithmId)` — Reference на Body по `#id-...`.
8. (в оригинале есть строка, перезаписывающая nodeValue SignatureMethod на c14n-URI —
   похоже на артефакт/баг; при воспроизведении опираться на корректный SignatureMethod из п.4 таблицы OID.)
9. `WSSecHeader(doc)`: `setMustUnderstand(true)`, `insertSecurityHeader()`, добавить в Header;
   в `wsse:Security` вложить `ds:Signature` (`header.getFirstChild().appendChild(sig.getElement())`).
   `wsse` namespace = `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`.
10. `SecurityTokenReference reference = new SecurityTokenReference(doc);
    reference.setKeyIdentifier(cert.getX509Certificate());` — кладёт серт как KeyIdentifier
    (base64 X509, ValueType v3). Добавляется в KeyInfo:
    `sig.getKeyInfo().addUnknownElement(reference.getElement())`.
11. `sig.sign(privateKey)`.
12. Сериализация через TransformerFactory → StreamResult (без доп. декларации).

Итоговая структура:
```
soap:Envelope
  soap:Header
    wsse:Security(mustUnderstand=1)
      ds:Signature
        ds:SignedInfo (C14N=exc-c14n, SignatureMethod=по OID, Reference URI="#id-<uuid>")
        ds:SignatureValue
        ds:KeyInfo
          wsse:SecurityTokenReference
            wsse:KeyIdentifier (base64 сертификата)
  soap:Body(wsu:Id="id-<uuid>")   ← то что подписано
```
Примечание: в NCANode серт передаётся через KeyIdentifier внутри SecurityTokenReference,
а НЕ через отдельный `wsse:BinarySecurityToken`+Reference URI. (В задании упомянут
BinarySecurityToken — здесь используется KeyIdentifier-вариант; если контрагент требует BST,
это надо реализовать отдельно.)

### WSSE VERIFY — `WsseService.verify`
1. Парс SOAP. `root = doc.getFirstChild()` (Envelope).
2. `signatures = root.getElementsByTagName("ds:Signature")`; если 0 → invalid.
3. Берётся ПЕРВАЯ подпись: `new XMLSignature(el, "")`.
4. Серт достаётся НЕ из KeyInfo напрямую, а из
   `wsse:SecurityTokenReference` → `ref.getKeyIdentifier(new CertificateStore(new X509Certificate[]{}))[0]`.
5. `signature.checkSignatureValue(cert.getPublicKey())` И `cert.isValid(...)`.

---

## 4. КЛЮЧИ — PKCS12 / KeyStore

### 4.1 SignerRequest (поля)
- `key` — PKCS12 в Base64 (обязателен).
- `password` — пароль контейнера (обязателен).
- `keyAlias` — nullable; если null → берётся ПЕРВЫЙ alias в хранилище.
- `referenceUri` — только для XML sign (Reference URI подписи данного signer).

WsseSignRequest — те же key/password/keyAlias, но одиночные (не список).

### 4.2 Чтение keystore — `KalkanWrapper.read(key, keyAlias, password)`
1. `KeyStore.getInstance("PKCS12", kalkanProvider)` — тип **PKCS12**, провайдер Kalkan.
2. `Base64.getDecoder().decode(key)` (ошибка → KEY_INVALID_BASE64).
3. `store.load(inputStream, password.toCharArray())`.
4. Маппинг ошибок Kalkan → свои сообщения:
   - "stream does not represent a PKCS12 key store" → KEY_INVALID_FORMAT
   - "PKCS12 key store mac invalid - wrong password or corrupted file." → KEY_INVALID_PASSWORD
   - иначе → KEY_UNKNOWN_ERROR
5. `KeyUtil.getAliases(store)` — enumerate `store.aliases()`. Пусто → ошибка.
6. Если `keyAlias != null` и его НЕТ среди aliases → ошибка KEY_ALIAS_NOT_FOUND.
   Иначе (в т.ч. когда передан валидный alias — тут в оригинале ветка else всё равно
   перезаписывает на aliases.get(0); фактически поведение: null или отсутствие → первый alias).
7. Возврат `KeyStoreWrapper(store, alias, password, aliases)`.

### 4.3 Извлечение ключа и серта — `KeyStoreWrapper`
- `getPrivateKey()` = `(PrivateKey) keyStore.getKey(alias, password.toCharArray())`
  (тот же пароль, что и на контейнер).
- `getCertificate()` = `(X509Certificate) keyStore.getCertificate(alias)` → CertificateWrapper.
  Берётся сертификат по alias (leaf); отдельной работы с цепочкой (getCertificateChain) в
  XML/WSSE пути НЕТ — в подпись кладётся только leaf-сертификат.

### 4.4 Для нашего KC_LoadKeyStore (native)
- Тип хранилища: PKCS12. Один пароль и на контейнер, и на приватный ключ.
- alias: поддержать «null → первый alias». Валидировать список алиасов.
- Из хранилища нужны: privateKey (по alias+password) и leaf X509 cert (по alias).
- OID алгоритма подписи брать из самого cert (getSigAlgOID) → далее таблица п.1.4.

---

## 5. Нюансы (сводка)

- Кодировка везде **UTF-8**; входной XML/SOAP `.trim()` перед парсингом.
- DOM обязательно **namespace-aware**.
- Префикс XMLDSIG жёстко `ds:` (поиск подписей `getElementsByTagName("ds:Signature")`).
- **XML (enveloped):** transforms = [enveloped-signature, C14N **with comments**];
  KeyInfo = X509Certificate; Reference URI = "" (весь док) или "#id"; подписи — прямые дети
  корня, добавляются по порядку, проверяются/снимаются в обратном (LIFO).
- **WSSE:** transforms = [**exclusive-c14n без комментариев**]; CanonicalizationMethod тоже
  exc-c14n; Reference = "#"+wsu:Id Body; серт в KeyInfo через
  SecurityTokenReference/KeyIdentifier (не X509Data, не BST); mustUnderstand=1.
- id-атрибуты: WSSE использует `wsu:Id` в WSU-namespace на Body. Для XML — атрибут, на который
  указывает referenceUri (должен быть зарегистрирован как ID, иначе Reference не разрезолвится).
- Множественная подпись — только для /xml (список signers), WSSE — одна подпись.
- Провайдер/алгоритмы: обязателен эквивалент `KncaXS.loadXMLSecurity()` — регистрация ГОСТ-URI;
  без него gost-подпись/дайджест не соберутся.
- Флаги запроса XML: `clearSignatures` (снять старые подписи до подписания),
  `trimXml` (удалить whitespace-текстноды — влияет на канонизацию, делать ДО подписи).


---

# Раздел 4 — OCSP / CRL / CA / конфигурация

## NCANode: OCSP / CRL / CA-валидация и конфигурация — извлечение для Go-порта

Источники: `service/OcspService.java`, `service/CrlService.java`, `service/CaService.java`,
`service/DirectoryService.java`, `util/Util.java`, `configuration/**`, `configuration/crl/**`,
`dto/ocsp/**`, `dto/crl/**`, `resources/application.yml`.

Общий принцип: любой URL-параметр в конфиге — это **строка из нескольких URL через пробелы**
(`Util.urlMap`), которая парсится в `Map<sha1(url) → URL>`. Ключ `sha1(url)` (HEX, верхний регистр,
UTF-8) используется и как имя файла в кэше. Разбиение по `split("\\s+")`, невалидные URL молча
отбрасываются с warning.

---

## 1. OCSP (`OcspService`, `OcspConfiguration`, `dto/ocsp/*`)

Назначение: онлайн-проверка отозванности сертификата на OCSP-серверах.

### Вход
`verify(CertificateWrapper cert, CertificateWrapper issuer) -> List<OcspStatus>`.
Возвращается **список** статусов — по одному на каждый URL из `ncanode.ocsp.url` (в дефолте один
`http://ocsp.pki.gov.kz/`). Для каждого URL цикл независим; ошибка одного не рушит остальные.

- Если `issuer == null` → сразу один статус `UNKOWN` с сообщением
  *"Cannot find root certificate in NCANode. Try add it using NCANODE_CA_URL variable."* (issuer
  берётся из `CaService.getRootCertificateFor`, см. п.3).

### Построение запроса (`buildOcspRequest`)
- `OCSPReqGenerator` (Kalkan).
- `CertificateID` c хэш-алгоритмом **`CertificateID.HASH_SHA256`** (издатель = issuer.X509,
  serialNumber = серийник проверяемого серта, provider = имя KalkanProvider). Т.е. CertID =
  hash(issuerName)+hash(issuerKey)+serial по SHA-256.
- **Nonce**: расширение `id_pkix_ocsp_nonce`, 8 случайных байт (`SecureRandom`), обёрнуто в
  **двойной** `DEROctetString` (`new DEROctetString(new DEROctetString(nonce))`), critical=false.
- Экстеншены ставятся через `setRequestExtensions(new X509Extensions(...))`.
- Запрос **не подписывается** (без requestorName).

### Отправка (`makeRequest`)
- HTTP **POST** на OCSP-URL, заголовок `Content-Type: application/ocsp-request`,
  тело = `request.getEncoded()` (DER), `ByteArrayEntity`. Общий `CloseableHttpClient` (см. п.4).
- Никаких отдельных OCSP-таймаутов/ретраев — только настройки общего http-клиента.
- URL берётся строго из конфига `ncanode.ocsp.url`; **AIA из сертификата НЕ используется**.

### Разбор ответа (`processOcspResponse`)
1. `OCSPResp resp`; если `resp.getStatus() != 0` (не `SUCCESSFUL`) → `UNKOWN`, message "Unknown status".
2. `BasicOCSPResp brep = resp.getResponseObject()`.
3. **Проверка nonce**: если в ответе есть `id_pkix_ocsp_nonce` — распаковывается двойной
   OctetString и сравнивается с отправленным; при несовпадении → `UNKOWN`, "Nonce aren't equals".
   Если nonce в ответе отсутствует — проверка пропускается (не ошибка).
4. Берётся **первый** `SingleResp` (`getResponses()[0]`), `getCertStatus()`:
   - `null` → `ACTIVE`, message "OK" (good).
   - `RevokedStatus` → `REVOKED`, заполняются `revocationTime` (`rev.getRevocationTime()`) и
     `revocationReason` (`rev.getRevocationReason()`, при `IllegalStateException` → **-1**), message "OK".
   - иначе (`UnknownStatus`) → `UNKOWN`, "Unknown status".
- **thisUpdate/nextUpdate НЕ читаются и не проверяются**, подпись ответа не верифицируется в этом коде.

### DTO
- `OcspResult` enum: `UNKOWN` (именно так, опечатка), `ACTIVE`, `REVOKED`.
- `OcspStatus` (`@Data @Builder`): `OcspResult result`, `Date revocationTime`, `int revocationReason`,
  `String message`, `String url`. Методы `isActive()` (== ACTIVE);
  `toCertificateRevocationStatus()` → `revoked = (result==REVOKED)`, `by = OCSP`, `reason = message`.
- `OcspConfiguration`: `@ConfigurationProperties("ncanode.ocsp")`, поле `url`, метод `getUrlList()`.

---

## 2. CRL (`CrlService`, `configuration/crl/*`, `dto/crl/*`)

Назначение: офлайн-проверка по скачанным CRL-файлам с фоновым обновлением кэша.
`CrlService` — **не** @Service, создаётся вручную бинами (см. `CrlBeanConfiguration`), существует в
**двух экземплярах** (см. п.4): `default` (для проверки конечных сертов) и `ca-crl` (для проверки
самих CA-сертов, см. п.3).

### Константы / раскладка кэша
- `CRL_DEFAULT="default"`, `CRL_CA="ca-crl"` (тип сервиса, передаётся в конструктор, идёт в логи).
- Каталоги кэша: `crl/full` (`CRL_CACHE_FULL_DIR_NAME`), `crl/delta` (`CRL_CACHE_DELTA_DIR_NAME`).
- Расширение файлов `.crl`. Имя файла при скачивании = `sha1(url).crl`.
- Физический путь = `<cacheDir>/<crl/full|crl/delta>/` (через `DirectoryService.getCachePathFor`,
  каталоги создаются автоматически).

### Планировщик обновления (два `@PostConstruct`)
- **Full**: если `ttl >= 1` — `PeriodicTrigger(ttl, MINUTES)`, `initialDelay=0`, `fixedRate=true`;
  задача `updateCache(false, crlConfiguration, "crl/full")`.
- **Delta**: если `delta.ttl >= 1` — аналогично с `delta` конфигом и каталогом `crl/delta`.
- Планировщик — общий `TaskScheduler` (пул 10 потоков, см. п.4).

### Обновление кэша (`updateCache`, `synchronized`)
- Дважды synchronized: на самом методе и на `directoryService` (глобальный лок кэша, общий с CaService).
- Ранний выход, если `!enabled` или `ttl <= 0`.
- Удаляет устаревшие файлы: файл считается актуальным (не удаляется), если
  `now - lastModified <= ttl*60000` мс; при `force=true` удаляются все.
- Скачивает недостающие: для каждого URL целевой файл `sha1(url).crl`; если файл уже существует —
  пропуск (не перекачивает). Иначе GET-скачивание. Логи "Nothing to update" / "N files updated".
- ВНИМАНИЕ: при удалении используется имя `sha1(url).crl` не участвует — удаляются все `.crl` в
  каталоге по возрасту, а докачиваются по именам-хэшам. Delta и full живут в разных каталогах.

### Проверка сертификата (`verify(CertificateWrapper cert) -> CrlStatus`)
- Если `!enabled` → сразу `ACTIVE`.
- Иначе перебирает каталоги в порядке **`crl/delta`, затем `crl/full`**; в каждом — все `.crl`
  файлы; грузит `X509CRL` (`CertificateFactory X.509`); `crl.isRevoked(cert.getX509Certificate())`.
  - При отзыве → `REVOKED` + `file` (имя файла), `revocationDate` (`entry.getRevocationDate()`),
    `reason` (`entry.getRevocationReason().toString()` или "").
- Если нигде не найден → `ACTIVE`.
- **Подпись CRL и её издатель/срок действия (nextUpdate) НЕ проверяются** — доверие к содержимому
  кэша полное; актуальность обеспечивается только TTL-перекачкой.

### Скачивание (`download` / `downloadCrl`)
- HTTP GET через общий клиент; статус ≠ 200 → `CrlException`; пустой entity → `CrlException`;
  тело пишется в файл. Ошибки скачивания логируются, но не бросаются наружу (в `downloadCrl`).

### DTO / конфиг
- `CrlResult` enum: `REVOKED`, `ACTIVE`.
- `CrlStatus` (`@Data @Builder`, поля final): `CrlResult result`, `String file`,
  `Date revocationDate`, `String reason`. `toCertificateRevocationStatus()` → `by = CRL`.
- Интерфейс `CrlConfiguration`: `isEnabled()`, `getTtl()`, `getUrl()`, `getUrlList()`, `getDelta()`.
- `CrlBaseConfiguration` (база): `enabled=true`, `Integer ttl`, `String url`,
  `CrlBaseConfiguration delta`, `getUrlList()=Util.urlMap(url)`.
- `DefaultCrlConfiguration` `@ConfigurationProperties("ncanode.crl")` `@Primary` — для default-сервиса.
- `CaCrlConfiguration` `@ConfigurationProperties("ncanode.ca.crl")` `@Qualifier("caCrlConfiguration")`
  — для ca-crl-сервиса.

---

## 3. CA (`CaService`, `CaConfiguration`)

Назначение: формирование набора доверенных корневых/промежуточных сертификатов УЦ и поиск издателя.
`@Service`, кэш в памяти `List<CertificateWrapper> certificates` + файлы на диске в `<cacheDir>/ca/`.

### Обновление кэша (`updateCache`)
- `@Scheduled(fixedRateString="${ncanode.ca.ttl}", initialDelay=0, timeUnit=MINUTES)` + `@Retryable(CaException.class)`.
  Плановый вызов работает только если `caConfiguration.isEnabled()`.
- `updateCache(boolean force)`: двойной `synchronized(directoryService){ synchronized(certificates){…}}`.
  - `certificates.clear()`.
  - Если список URL пуст → лог ошибки + **`shutdown()`** (`SpringApplication.exit` + `System.exit(32)`).
  - Для каждого URL: файл `<cacheDir>/ca/<sha1(url)>.cer`.
    - если `force` или файла нет/не читается → `downloadCert(url, file)`; иначе грузит из файла.
    - `checkCertForNull`: если серт `null` → лог + **shutdown(32)**.
    - если серт **просрочен** (`!isDateValid()`) **или** ca-crl-сервис вернул `REVOKED` для него →
      перекачать (в коде `downloadCert` вызывается дважды подряд — фактически повторное скачивание).
    - повторный `checkCertForNull`.
- Т.е. сами CA-серты тоже проверяются на отозванность через отдельный **`caCrlService`**
  (CRL по `ncanode.ca.crl.url`, каталоги `crl/full`/`crl/delta` того же кэша).

### Поиск издателя (`getRootCertificateFor`) — ключевое для OCSP
```
if (issuerX500 == subjectX500) return empty();   // самоподписанный корень → нет "родителя"
return getRootCertificates().stream()
   .filter(root -> cert.issuerX500 == root.subjectX500 && cert.verify(root.publicKey))
   .findFirst();
```
Т.е. issuer выбирается по совпадению `issuerDN==subjectDN` **и** успешной криптопроверке подписи
серта публичным ключом кандидата. Результат передаётся как `issuer` в `OcspService.verify`.

### `getRootCertificates`
- Если in-memory список не пуст — возвращает его; иначе читает все `*.cer` из `<cacheDir>/ca/`,
  парсит в `CertificateWrapper` и кэширует. Потокобезопасно (те же два лока).

### Загрузка (`download`)
- HTTP GET общим клиентом; статус ≠ 200 → `CaException`; пустой entity → `CaException`; пишет в файл.

### `CaConfiguration`
`@ConfigurationProperties("ncanode.ca")`: `boolean enabled=true`, `String url`, `Integer ttl`,
`getUrlList()=Util.urlMap(url)`.

---

## 4. Полная таблица конфигурации (application.yml + *Configuration.java)

| Свойство (yaml) | Env-переменная | Дефолт | Назначение |
|---|---|---|---|
| `server.port` | `NCANODE_PORT` | `14579` | HTTP-порт сервиса |
| `spring.main.banner-mode` | — | `off` | без баннера Spring |
| `ncanode.system.detailedErrors` | `NCANODE_DEBUG` | `false` | подробные ошибки в ответах |
| `ncanode.system.cacheDir` | `NCANODE_CACHE_DIR` | `./cache` | корень файлового кэша (ca/, crl/full, crl/delta) |
| `ncanode.crl.enabled` | `NCANODE_CRL_ENABLED` | `true` | вкл/выкл проверку по CRL |
| `ncanode.crl.ttl` | `NCANODE_CRL_TTL` | `1440` (мин) | TTL/период обновления full-CRL |
| `ncanode.crl.url` | `NCANODE_CRL_URL` | `http://crl.pki.gov.kz/nca_rsa_2022.crl http://crl.pki.gov.kz/nca_gost_2022.crl` | список full-CRL (через пробел) |
| `ncanode.crl.delta.url` | `NCANODE_CRL_DELTA_URL` | `http://crl.pki.gov.kz/nca_d_rsa_2022.crl http://crl.pki.gov.kz/nca_d_gost_2022.crl` | список delta-CRL |
| `ncanode.crl.delta.ttl` | `NCANODE_CRL_DELTA_TTL` | `60` (мин) | период обновления delta-CRL |
| `ncanode.http-client.connectionTtl` | `NCANODE_HTTP_CLIENT_CONNECTION_TTL` | `10` (сек) | connection time-to-live http-клиента |
| `ncanode.http-client.userAgent` | `NCANODE_HTTP_CLIENT_USER_AGENT` | `""` → `NCANode/<version>` | User-Agent |
| `ncanode.http-client.proxy.url` | `NCANODE_PROXY_URL` | `""` | URL прокси (host:port:proto из URL) |
| `ncanode.http-client.proxy.username` | `NCANODE_PROXY_USERNAME` | `""` | логин прокси (Basic) |
| `ncanode.http-client.proxy.password` | `NCANODE_PROXY_PASSWORD` | `""` | пароль прокси |
| `ncanode.ocsp.url` | `NCANODE_OCSP_URL` | `http://ocsp.pki.gov.kz/` | список OCSP-серверов |
| `ncanode.ca.url` | `NCANODE_CA_URL` | 6 URL (см. ниже) | список сертификатов УЦ |
| `ncanode.ca.ttl` | `NCANODE_CA_TTL` | `1440` (мин) | период обновления CA-кэша |
| `ncanode.ca.enabled` | — (нет env; поле `enabled=true`) | `true` | вкл обновление CA |
| `ncanode.ca.crl.enabled` | `NCANODE_CA_CRL_ENABLED` | `true` | проверять CA-серты по CRL |
| `ncanode.ca.crl.ttl` | `NCANODE_CA_CRL_TTL` | `1440` (мин) | TTL ca-crl |
| `ncanode.ca.crl.url` | `NCANODE_CA_CRL_URL` | `http://crl.root.gov.kz/gost.crl http://crl.root.gov.kz/rsa.crl http://crl.root.gov.kz/gost2020.crl http://crl.root.gov.kz/rsa2020.crl` | CRL для проверки CA |
| `ncanode.ca.crl.delta.*` | — | `enabled:false`, url/ttl пусты | delta для ca-crl отключён |
| `ncanode.tsp.url` | `NCANODE_TSP_URL` | `http://tsp.pki.gov.kz/` | TSP (метки времени) |
| `ncanode.tsp.retries` | `NCANODE_TSP_RETRIES` | `3` (min 1) | число ретраев TSP |
| `springdoc.*` / `SWAGGER_RELATIVE_PATH` | `SWAGGER_RELATIVE_PATH` | `""` | Swagger UI |

Дефолт `NCANODE_CA_URL` (6 шт.):
`http://pki.gov.kz/cert/nca_rsa.crt`, `http://pki.gov.kz/cert/nca_gost.crt`,
`http://pki.gov.kz/cert/root_gost_2022.cer`, `http://root.gov.kz/cert/root_gost_2020.cer`,
`http://root.gov.kz/cert/root_rsa_2020.cer`, `http://pki.gov.kz/cert/nca_gost_2022.cer`.

### HTTP-клиент (`HttpClientConfiguration`, prefix `ncanode.http-client`)
- Один общий `CloseableHttpClient` (`@Scope(PROTOTYPE)` бин, инжектится в Ocsp/Crl/Ca).
- Прокси: если `proxy.url` не пуст → `HttpHost(host,port,proto)`; если задан username → Basic-креды
  через `BasicCredentialsProvider`/`AuthScope`.
- `setConnectionTimeToLive(connectionTtl, SECONDS)` (по умолч. 10с), `LaxRedirectStrategy`
  (следует за редиректами, в т.ч. POST), `disableCookieManagement()`.
- **Явных socket/connect-таймаутов нет** — только connection TTL; ретраев на уровне клиента нет.

### Пулы / async / scheduler
- `TaskConfiguration`: `ThreadPoolTaskScheduler`, poolSize **10**, префикс `ThreadPoolTaskScheduler`
  — используется CRL-планировщиком (full+delta, для обоих экземпляров сервиса).
- `AsyncConfiguration`: `@EnableAsync`, `getAsyncExecutor()` = дефолтный `ThreadPoolTaskExecutor`
  (без явной настройки размеров).
- CA использует Spring `@Scheduled` (отдельный планировщик Spring) + `@Retryable`.
- `CorsConfiguration`: CORS `/**`, разрешены все методы.
- `CrlBeanConfiguration`: два бина `CrlService` —
  `crlService` (`@Primary`, тип `default`, конфиг `DefaultCrlConfiguration`) и
  `caCrlService` (`@Qualifier("caCrlService")`, тип `ca-crl`, конфиг `caCrlConfiguration`).

---

## 5. KalkanConfiguration (провайдер/крипто-либа)

- `@Configuration`; бин `kalkanProvider()` (`@Scope SINGLETON`):
  - `new KalkanProvider()` → `Security.addProvider(kalkanProvider)` (регистрация JCE-провайдера РК).
  - `KncaXS.loadXMLSecurity()` — инициализация XML-DSIG (для XML-подписей).
  - Логирует версию KalkanCrypt (`getImplementationVersion()`).
- **Никаких путей к сертификатам/файлам провайдера в конфиге нет** — Kalkan подтягивается как
  jar-зависимость (`kz.gov.pki.kalkan.*`), встроенные алгоритмы/OID'ы идут из библиотеки.
- Имя провайдера (`kalkanProvider.getName()`) передаётся в `CertificateID`/крипто-операции OCSP.
- OID→digest маппинг для подписей — в `Util.getDigestAlgorithmOidBYSignAlgorithmOid`:
  RSA-SHA1, RSA-SHA256, GOST2015-256 (`1.2.398.3.10.1.1.2.3.1`), GOST2015-512
  (`1.2.398.3.10.1.1.2.3.2`), иначе GOST34311-95.

---

## 6. Нюансы для Go-порта (таймауты, ретраи, потокобезопасность, планировщик)

- **Таймауты**: специфичных connect/read таймаутов нет — только `connectionTtl` (10с TTL соединения).
  В Go задать разумные `http.Client{Timeout}` для OCSP/CRL/CA GET/POST.
- **Ретраи**: только CA-обновление (`@Retryable(CaException)`) и TSP (`retries=3`).
  OCSP и CRL-скачивание — без ретраев; OCSP-ошибка по URL просто даёт статус `UNKOWN`.
- **Отказоустойчивость OCSP**: несколько URL → несколько независимых статусов (список), не «первый
  успешный». Вызывающий код сам решает, как агрегировать (в Go учесть).
- **Потокобезопасность**: файловый кэш защищён `synchronized(directoryService)` — единый глобальный
  лок на все операции с кэшем (CA + CRL). `CaService.certificates` дополнительно под своим локом.
  `CrlService.updateCache` — `synchronized` метод. В Go → общий `sync.Mutex` на директорию кэша.
- **Планировщик**: CRL — `PeriodicTrigger fixedRate initialDelay=0` (старт сразу, затем каждые ttl мин),
  отдельно full и delta; CA — Spring `@Scheduled fixedRate=ca.ttl` initialDelay=0. В Go → тикеры
  с немедленным первым запуском.
- **Имя файла кэша = `sha1(url)`** (HEX upper, UTF-8) — обязательно воспроизвести побайтово, если
  хотите переиспользовать существующий кэш; иначе можно свою схему.
- **Fatal-поведение CA**: пустой список CA-URL или нечитаемый CA-серт → `System.exit(32)`. В Go
  лучше вернуть ошибку старта, а не убивать процесс (но семантику «без CA нельзя работать» сохранить).
- **Слабые места оригинала** (можно усилить в Go): не проверяются подпись/nextUpdate у CRL и
  подпись/thisUpdate/nextUpdate у OCSP-ответа; OCSP nonce — только если сервер его вернул; CertID
  всегда SHA-256 (некоторые серверы РК могут требовать иной hash — учесть при совместимости).
- **Опечатка в enum** `OcspResult.UNKOWN` — в API-ответах NCANode это значение так и сериализуется;
  если нужен байт-в-байт совместимый JSON, повторить написание.


---

# Раздел 5 — PDF / JWT / API

## NCANode → Go: PDF-подпись, JWT-GOST, полный API-контракт

Извлечено из исходников NCANode 3.0.0 (Spring Boot 2.7.2, Java 17).
Источники: `service/PdfService.java`, `service/JwtService.java`, `controller/*`, `dto/*`, `exception/*`, `controller/advice/*`, `constants/MessageConstants.java`, `build.gradle`.

---

## 1. PDF-подпись

### Библиотека
- **Apache PDFBox 2.0.29** — `org.apache.pdfbox:pdfbox:2.0.29` (build.gradle стр. 72).
- **Лицензия: Apache License 2.0** — разрешительная, permissive, совместима с коммерческим/закрытым кодом, атрибуция без copyleft. Это ВАЖНО: PDFBox — не iText/OpenPDF.
  - Для сравнения: iText 7 = AGPL (вирусный copyleft, требует покупки коммерческой лицензии), OpenPDF = LGPL/MPL. NCANode сознательно на PDFBox именно чтобы избежать AGPL.
- Дополнительно (не для PDF-структуры, а как криптопровайдер BC): `org.bouncycastle:bcprov-jdk15on:1.70`, `org.bouncycastle:bcpkix-jdk15on:1.70`. Но фактическая крипто-подпись CMS делается через **KalkanProvider** (`KalkanProvider.PROVIDER_NAME`), а не BC.

### Как встраивается ЭЦП (PAdES / CAdES-detached)
Подпись — это **incremental update PDF** с CMS/PKCS#7 detached в словаре подписи:
- `PDSignature` c `Filter = ADOBE.PPKLITE`, `SubFilter = ETSI.CAdES.detached` (PAdES-BES; строка `signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED)`). Закомментирован альтернативный `ADBE_PKCS7_DETACHED`.
- Метаданные подписи: `name` = SubjectDN сертификата, `location`, `reason`, `contactInfo` (из запроса), `signDate` = текущее время.
- `document.addSignature(signature, SignatureInterface)` затем `document.saveIncremental(outputStream)` — PDFBox сам вычисляет `/ByteRange`, вызывает callback `sign(InputStream content)` для получения CMS-байтов и вставляет их в `/Contents`.

### Как формируется CMS (внутри callback `PdfSignatureInterface.sign`)
1. Читает весь `content` (диапазон ByteRange) в байты.
2. `CMSSignedDataGenerator` (Kalkan-версия из `kz.gov.pki.kalkan.jce.provider.cms.*`).
3. `generator.addSigner(privateKey, cert, digestOid)` где digestOid определяется из OID алгоритма подписи сертификата через `Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getSigAlgOID())`:
   - `sha1WithRSA` → DIGEST_SHA1
   - `sha256WithRSA` → DIGEST_SHA256
   - OID `1.2.398.3.10.1.1.2.3.1` (ГОСТ-2015-256) → DIGEST_GOST3411_2015_256
   - OID `1.2.398.3.10.1.1.2.3.2` (ГОСТ-2015-512) → DIGEST_GOST3411_2015_512
   - иначе → DIGEST_GOST34311_95 (старый ГОСТ-2004)
4. `generator.addCertificatesAndCRLs(certStore)` — вкладывает сам сертификат подписанта.
5. `generator.generate(new CMSProcessableByteArray(contentBytes), false, KalkanProvider)` — **encapsulate = false → detached CMS**.
6. Если `withTsp=true`: для каждого SignerInformation добавляется TSP-метка времени (`tspService.addTspToSigner(signer, cert, policyId)`), затем `CMSSignedData.replaceSigners(...)`. Политика TSA берётся из `tsaPolicy` запроса, по умолчанию `TSA_GOST2015_POLICY`.
7. Возвращает `signedData.getEncoded()`.

Хеширование: не отдельным шагом — digest вычисляется внутри Kalkan CMS-генератора по выбранному digest-OID над байтами ByteRange.

### Как verify извлекает подписи
1. Base64-decode PDF → `PDDocument.load`.
2. `document.getSignatureDictionaries()` → список `PDSignature`. Если пусто → `NoSignaturesFoundException` (HTTP 404).
3. Для каждой подписи:
   - `signature.getContents()` = сырой CMS (`/Contents`); если пусто → invalid "Empty signature contents".
   - `signature.getSignedContent(is)` = подписанный контент по `/ByteRange`.
   - `new CMSSignedData(new CMSProcessableByteArray(signedContent), signatureContent)` → парсит CMS.
   - Для каждого `SignerInformation`: достаёт сертификат из CMS-мешка (`getCertificatesAndCRLs("Collection", KalkanProvider)` по `si.getSID()`).
   - Крипто-проверка: `si.verify(x509.getPublicKey(), KalkanProvider.PROVIDER_NAME)`.
   - Доверие+отзыв: `certificateService.attachValidationData(wrapper, withOcsp, withCrl)` + `wrapper.isValid(now, withOcsp, withCrl)` (OCSP/CRL по `revocationCheck`).
   - digest OID сообщается через `si.getDigestAlgOID()`.
4. Ответ: `valid` = И всех подписантов; `signers` = список `PdfSignerInfo`.

### DTO
**PdfSignRequest**: `pdf` (Base64, @NotEmpty), `signers: List<PdfSigner>` (@NotEmpty), `withTsp: bool=false`, `tsaPolicy: TsaPolicy`.
- **PdfSigner**: `reason`, `location`, `contactInfo`, `signer: SignerRequest` (@NotEmpty).
- **SignerRequest**: `key` (Base64 PKCS12, @NotEmpty), `password` (@NotEmpty), `keyAlias`, `referenceUri`.
- **TsaPolicy** (enum): `TSA_GOST2015_POLICY`, `TSA_GOST_POLICY`, `TSA_GOSTGT_POLICY` (значения = OID из KNCAObjectIdentifiers).

**PdfSignResponse** extends StatusResponse: `pdf` (Base64 подписанного PDF) + `status`(=200), `message`(="OK").

**PdfVerifyRequest** extends VerifyRequest: `pdf` (@NotEmpty) + `revocationCheck: Set<CertificateRevocation>` (default пусто).

**PdfVerificationResponse** extends StatusResponse: `valid: bool`, `signers: List<PdfSignerInfo>`.

**PdfSignerInfo**: `valid: bool`, `reason`, `location`, `contactInfo`, `signDate: Date`, `certificate: CertificateInfo`, `signatureAlgorithm` (= SubFilter, напр. `ETSI.CAdES.detached`), `digestAlgorithm` (= CMS digest OID или "unknown").

### Что нужно на Go (аналог)
- Библиотеки PDFBox в Go нет; нужно самому реализовать incremental-update PAdES:
  - Парсинг PDF/xref, вставка signature dictionary с плейсхолдером `/Contents`, вычисление `/ByteRange`, дозапись (incremental update). Кандидаты: `github.com/pdfcpu/pdfcpu` (Apache-2.0) для парсинга/записи, либо `github.com/digitorus/pdfsign` (детально делает ByteRange+CMS placeholder, MIT) — самый близкий аналог, но CMS-подпись там через стандартный crypto; ГОСТ-подпись/digest придётся подменять на нативный Kalkan/наш CMS-генератор.
  - CMS detached с ГОСТ-3411/3410 — не покрывается стандартной Go crypto; требуется вызов нативного слоя (как весь остальной сервис к Kalkan) либо своя ASN.1 CMS-сборка с ГОСТ digest/sign OID-ами (см. OID-маппинг выше) и TSP-токеном.
  - verify: разобрать ByteRange, распарсить CMS (ASN.1), проверить подпись ГОСТ-ключом, вынуть сертификат, проверить цепочку+OCSP/CRL.
- Итог: PDFBox отвечает только за структуру PDF (ByteRange, incremental save) — это переносимая часть; крипто уже вне PDFBox (Kalkan CMS). На Go разумно: pdfcpu/digitorus для структуры + наш нативный CMS-слой для ГОСТ.

---

## 2. JWT-GOST

Библиотека: **`kz.gov.pki:java-jwt:4.4.0`** — это форк auth0 java-jwt с добавленными ГОСТ-алгоритмами (`Algorithm.GG2015`, `Algorithm.GG2004`). Пакеты импорта — `com.auth0.jwt.*`. Провайдер подписи — внутри форка (Kalkan/ГОСТ), NCANode напрямую провайдер не указывает, только тип ключа `ECPublicKey/ECPrivateKey`.

### Header
- `alg` — из запроса (`jwt.header.alg`), обязателен. Поддержка: `GG2015`, `GG2004` (ГОСТ), `ES256/384/512`, `RS256/384/512`.
- `typ` — из запроса (@NotEmpty), обычно `JWT`.
- **x5c НЕ используется** — сертификат в JWT не встраивается. При decode сертификат передаётся отдельным полем `key` в запросе.

### Claims (payload)
Произвольные — `JwtPayload` собирает всё через `@JsonAnySetter` в `Map<String,Object>`. При encode каждый claim добавляется типизированно (`addClaim`): String/Integer/Long/Double/Boolean, иначе `toString()`. Стандартных claim-ов (exp/iss) сервис сам не навязывает.

### Подпись (encode)
1. `kalkanWrapper.read(key, keyAlias, password)` → KeyStore (PKCS12).
2. `JWT.create()`, добавляет все claims.
3. `resolveAlgorithm(alg, cert.publicKey, keystore.privateKey)` → `Algorithm.GG2015((ECPublicKey)pub, (ECPrivateKey)priv)` и т.д.
4. `builder.sign(algorithm)` → компактный JWT-строка.
- Ошибка ключа → `ClientException` (400); прочее → `ServerException` (500).

### Проверка (decode)
1. `CertificateService.load(base64(key))` → X509 сертификат (пробелы вырезаются).
2. `JWT.decode(jwt)` (JWTDecodeException → ClientException 400).
3. `resolveAlgorithm(data.getAlgorithm(), x509.getPublicKey())` — алгоритм берётся из header самого JWT.
4. `JWT.require(alg).build().verify(jwt)`; при `JWTVerificationException` → `valid=false` (НЕ ошибка, 200 с valid=false).
5. Собирает payload (все claims как Object) и header (только `alg`, `typ`).

### DTO
**JwtEncodeRequest**: `jwt: JwtRequest` (@NotNull @Valid), `key` (@NotEmpty), `password` (@NotEmpty), `keyAlias`.
- **JwtRequest**: `header: JwtHeader` (@NotNull), `payload: JwtPayload` (@NotNull).
- **JwtHeader**: `alg` (@NotEmpty), `typ` (@NotEmpty).
- **JwtPayload**: динамическая мапа claims (`@JsonAnySetter/@JsonAnyGetter`).

**JwtEncodeResponse** extends StatusResponse: `jwt: String` (+ status/message).

**JwtDecodeRequest**: `jwt` (@NotNull), `key` (Base64 X509 сертификат, @NotEmpty).

**JwtDecodeResponse** extends StatusResponse: `valid: bool`, `jwt: Jwt{ header: Map<String,String>, payload: Map<String,Object> }`.

### Что нужно на Go
- ГОСТ-alg (GG2015/GG2004) нет в Go JWT-либах — подпись/верификация через нативный ГОСТ-слой. RS*/ES* можно стандартным `golang-jwt`. Формат JWT (base64url header.payload.signature) стандартный; отличается только алгоритм подписи над `header.payload`.
- x5c не нужен; сертификат приходит отдельным полем.

---

## 3. Полный API (все контроллеры, все — POST, JSON, base path /)

| Path | Method | Request DTO (поля) | Response DTO (поля) |
|---|---|---|---|
| `/pdf/sign` | POST | PdfSignRequest: pdf, signers[], withTsp, tsaPolicy | PdfSignResponse: pdf, status, message |
| `/pdf/verify` | POST | PdfVerifyRequest: pdf, revocationCheck | PdfVerificationResponse: valid, signers[], status, message |
| `/jwt/encode` | POST | JwtEncodeRequest: jwt{header,payload}, key, password, keyAlias | JwtEncodeResponse: jwt, status, message |
| `/jwt/decode` | POST | JwtDecodeRequest: jwt, key | JwtDecodeResponse: valid, jwt{header,payload}, status, message |
| `/cms/sign` | POST | CmsCreateRequest | CmsResponse (cms) |
| `/cms/sign/add` | POST | CmsCreateRequest | CmsResponse (cms) |
| `/cms/verify` | POST | CmsVerifyRequest: cms, data, revocationCheck | CmsVerificationResponse |
| `/cms/extract` | POST | CmsVerifyRequest: cms | CmsDataResponse |
| `/xml/sign` | POST | XmlSignRequest | XmlSignResponse (xml) |
| `/xml/verify` | POST | XmlVerifyRequest: xml, revocationCheck | VerificationResponse |
| `/wsse/sign` | POST | WsseSignRequest | XmlSignResponse |
| `/wsse/verify` | POST | XmlVerifyRequest: xml, revocationCheck | VerificationResponse |
| `/x509/info` | POST | X509InfoRequest: certs, revocationCheck | VerificationResponse |
| `/x509/verify` | POST | SbaVerifyRequest: certificate, signature, data, revocationCheck | VerificationResponse |
| `/pkcs12/info` | POST | Pkcs12InfoRequest (keys/...) | VerificationResponse |
| `/pkcs12/aliases` | POST | Pkcs12InfoRequest: keys | Pkcs12AliasesResponse: aliases[][] |
| `/` | GET (text/html) | — | HTML home page (версия, баннер) |

Примечания:
- `revocationCheck` везде — `Set<CertificateRevocation>` (`OCSP`, `CRL`), default пусто (проверка отзыва отключена).
- Все success-response наследуют **StatusResponse** (`status=200`, `message="OK"`).
- `CertificateInfo` (внутри signer/verification): valid, revocations[], notBefore, notAfter, keyUsage, serialNumber, signAlg, keyUser[], publicKey, signature, subject, issuer.
- (CMS/XML/WSSE/X509/Pkcs12 request/response-поля частично вне запрошенного объёма — здесь только то, что видно из контроллеров/общих DTO.)

---

## 4. Ошибки: маппинг исключений → HTTP

Единый обработчик `ExceptionHandlerControllerAdvice` ловит все `RuntimeException`:
- Базовый `ApplicationException` (abstract) имеет `getStatus()`. По нему берётся HTTP-статус.
- Не-ApplicationException RuntimeException → **500**.
- Тело — **ErrorResponse** (extends StatusResponse, JsonInclude NON_NULL): `status`, `message` (= `e.getMessage()`), `details` (= `e.getCause().getMessage()`, только если `systemConfiguration.detailedErrors=true`).

| Исключение | HTTP статус | Тип |
|---|---|---|
| `ClientException` | **400** BAD_REQUEST | ApplicationException |
| `ServerException` | **500** INTERNAL_SERVER_ERROR | ApplicationException |
| `NoSignaturesFoundException` | **404** NOT_FOUND | ApplicationException (PDF verify без подписей) |
| `KeyException` | (не RuntimeException — checked) обычно оборачивается в ClientException(400) | Exception |
| `CaException`, `CrlException`, `TspException` | 500 (обычный RuntimeException, нет getStatus) | RuntimeException |

Поведение сервисов:
- JwtService.encode: KeyException → ClientException(400); прочее → ServerException(500).
- JwtService.decode: JWTDecodeException/ошибки → ClientException(400); неверная подпись → 200 `valid:false`.
- PdfService.sign: любое исключение → ServerException(500).
- PdfService.verify: нет подписей → NoSignaturesFoundException(404); прочее → ServerException(500).

### MessageConstants (все сообщения)
Только KeyService/сертификаты (PDF/JWT своих констант не имеют, используют `e.getMessage()`):
- `KEY_INVALID_BASE64` = "Key reading error: Invalid Base64 format. Key must be in valid Base64 format."
- `KEY_INVALID_FORMAT` = "Key reading error: Invalid format."
- `KEY_INVALID_PASSWORD` = "Key reading error: Password incorrect."
- `KEY_UNKNOWN_ERROR` = "Key reading error: Unknown error. Please see logs."
- `KEY_ENGINE_ERROR` = "Key reading error: Engine error. Please see logs."
- `KEY_ALIASES_NOT_FOUND` = "Key reading error: Key does not have aliases."
- `KEY_ALIAS_NOT_FOUND` = "Key reading error: Key does not have '%s' alias"
- `KEY_CANT_EXTRACT_PRIVATE_KEY` = "Key reading error: Cannot extract private key."
- `KEY_CANT_EXTRACT_CERTIFICATE` = "Key reading error: Cannot extract certificate."
- `CERT_INVALID` = "[%d]: Invalid certificate given."

---

## 5. build.gradle — ключевые зависимости с версиями

**Платформа**: Spring Boot 2.7.2, Java 17, war-упаковка (Tomcat provided).

**Крипто / Kalkan (нативные .jar из `lib/` flatDir)**:
- `knca_provider_jce_kalkan-0.7.5` (KalkanProvider — ядро ГОСТ РК)
- `kalkancrypt-xmldsig-0.5` (XML-DSig ГОСТ)
- `org.apache.santuario:xmlsec:3.0.3`

**BouncyCastle** (для PDFBox/CMS-вспом.):
- `org.bouncycastle:bcprov-jdk15on:1.70`
- `org.bouncycastle:bcpkix-jdk15on:1.70`
(Фактическая CMS-подпись — через Kalkan-провайдер, не BC.)

**PDF**:
- `org.apache.pdfbox:pdfbox:2.0.29` — **Apache 2.0 (permissive)**.

**JWT**:
- `kz.gov.pki:java-jwt:4.4.0` — форк auth0 java-jwt c ГОСТ-алгоритмами GG2015/GG2004 (репозиторий Azure `pkgs.dev.azure.com/as1an/public`).

**SOAP/WSSE/XML**:
- `org.apache.ws.security:wss4j:1.6.19`
- `org.apache.wss4j:wss4j-ws-security-dom:2.4.1`
- `jakarta.xml.ws:jakarta.xml.ws-api:3.0.1`, `com.sun.xml.ws:jaxws-rt:3.0.2`

**HTTP-клиент** (для OCSP/CRL/TSP):
- `org.apache.httpcomponents:httpclient:4.5.13`

**Spring доп.**:
- spring-boot-starter-web / actuator / validation / cache
- `org.springframework:spring-aspects:5.3.23`, `org.springframework.retry:spring-retry:1.3.3`
- `org.springdoc:springdoc-openapi-ui:1.8.0` (Swagger)
- `org.codehaus.groovy:groovy-all:3.0.13`

**Репозитории**: flatDir `lib/` (Kalkan jar-ы), mavenLocal, mavenCentral, Azure feed `as1an/public` (java-jwt ГОСТ).

---

## Ключевые выводы для Go-порта
1. **PDF-структуру** делает PDFBox (Apache-2.0) — переносимо; на Go ближайший аналог `digitorus/pdfsign` (MIT, реализует ByteRange+CMS placeholder) или `pdfcpu` (Apache-2.0). PDFBox отвечает ТОЛЬКО за incremental-update/ByteRange, крипто уже вне его.
2. **CMS-подпись PDF** — detached CMS через Kalkan с ГОСТ digest-OID (маппинг в Util); TSP опционально (по умолчанию GOST2015-политика). Это нативная часть — на Go идёт через тот же native-слой, что и весь сервис.
3. **JWT** — стандартный компактный формат; ГОСТ только в alg GG2015/GG2004 (форк auth0 java-jwt). x5c НЕ используется, сертификат для verify приходит отдельным полем `key`. RS*/ES* можно чистым Go, ГОСТ — нативно.
4. **API** — 15 POST-эндпоинтов + GET `/`; все success наследуют StatusResponse(status=200,message=OK); revocationCheck=Set{OCSP,CRL}, по умолчанию отзыв не проверяется.
5. **Ошибки** — единый advice: ClientException→400, NoSignaturesFoundException→404, ServerException/прочее→500; тело ErrorResponse{status,message,details?}, details только при detailedErrors=true.
