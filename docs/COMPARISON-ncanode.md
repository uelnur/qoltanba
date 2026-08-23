# Сравнение с NCANode v3 (паритет по возможностям и полям)

Сопоставление нашего проекта с **NCANode v3** — популярным open-source сервисом
ЭЦП РК на Java (`ncanode-kz/NCANode`, спецификация
<https://v3.ncanode.kz/swagger-ui/openapi.yml>).

**Главное:** NCANode — обёртка над тем же криптоядром **Kalkan**
(`knca_provider_jce_kalkan`, Java JCE), что и мы (только мы через нативный
`libkalkancryptwr`/C-API). Поэтому доступ к данным у нас **тот же или шире** — всё,
что NCANode отдаёт, мы либо уже эмпирически извлекли пробником, либо выводим/парсим
из тех же байтов. Ниже — построчная сверка.

## Итог

- ✅ **Все поля NCANode мы можем возвращать** — паритет полный.
- ➕ **Мы можем возвращать больше** (см. раздел «Сверх NCANode»).
- ⚠️ **Два эндпоинта NCANode вне Kalkan-C-API** (PDF, JWT) — реализуемы нами, но
  требуют доп. библиотек/кода, не самого Kalkan.

---

## 1. Эндпоинты

| NCANode v3 | Назначение | У нас | Источник (Kalkan) |
|------------|-----------|-------|-------------------|
| `/pkcs12/info`, `/pkcs12/aliases` | инфо/алиасы ключа | ✅ | `KC_LoadKeyStore` + `X509ExportCertificateFromStore` |
| `/x509/info` | разбор сертификата | ✅ | `X509CertificateGetInfo` (эмпирически — все поля) |
| `/x509/verify` | валидация сертификата | ✅ | `X509ValidateCertificate` (OCSP/CRL — проверено) |
| `/cms/sign`, `/cms/sign/add` | подпись / со-подпись CMS | ✅ | `SignData` (+ `inSign` для со-подписи — проверено) |
| `/cms/verify` | проверка CMS | ✅ | `VerifyData` |
| `/cms/extract` | извлечь исходные данные | ✅ | `VerifyData` (восстановление контента — проверено) |
| `/xml/sign`, `/xml/verify` | подпись/проверка XML | ✅ | `SignXML` / `VerifyXML` |
| `/wsse/sign`, `/wsse/verify` | WS-Security | ✅ | `SignWSSE` / `VerifyXML` |
| `/pdf/sign`, `/pdf/verify` | подпись PDF | ⚠️ | **нет в Kalkan-C-API** — нужен PDF-слой (см. §4) |
| `/jwt/encode`, `/jwt/decode` | JWT (GOST) | ⚠️ | **нет в Kalkan** — реализуемо самим (hash+sign+base64url) |

> Примечание: `/pdf` и `/jwt` есть в master NCANode; в живой v3-спеке набор —
> pkcs12/x509/cms/xml/wsse. У нас дополнительно планируются транспорты (REST/gRPC/
> socket/MQ, batch, async) — этого у NCANode нет.

---

## 2. Поля сертификата — построчная сверка

### `CertificateSubject` (subject/issuer)

| NCANode | Наш источник | Статус |
|---------|--------------|--------|
| `commonName` | `SUBJECT_COMMONNAME` | ✅ проверено |
| `lastName` (фамилия) | `SUBJECT_SURNAME` | ✅ проверено |
| `surName` (имя/отчество) | `SUBJECT_GIVENNAME` | ✅ проверено |
| `email` | `SUBJECT_EMAIL` | ✅ (когда есть в серте) |
| `organization` | `SUBJECT_ORG_NAME` | ✅ проверено (ЮЛ) |
| `gender` (NONE/MALE/FEMALE) | вывод из ИИН (7-я цифра) | ✅ вычисляем сами |
| `iin` | парсинг `SUBJECT_SERIALNUMBER` (`IIN…`) | ✅ проверено |
| `bin` | парсинг `SUBJECT_ORGUNIT_NAME` (`BIN…`) | ✅ проверено |
| `country` | `SUBJECT_COUNTRYNAME` | ✅ проверено |
| `locality` | `SUBJECT_LOCALITYNAME` | ✅ (когда есть) |
| `state` | `SUBJECT_SOPN` | ✅ (когда есть) |
| `dn` | `SUBJECT_DN` / `ISSUER_DN` | ✅ проверено |

### `CertificateInfo`

| NCANode | Наш источник | Статус |
|---------|--------------|--------|
| `valid` | `X509ValidateCertificate` / verify rc | ✅ |
| `revocations[]` | OCSP/CRL валидация | ✅ проверено (good/revoked) |
| `notBefore`, `notAfter` | `NOTBEFORE`/`NOTAFTER` | ✅ проверено |
| `keyUsage` (UNKNOWN/AUTH/SIGN) | вывод из `KEY_USAGE`+`EXT_KEY_USAGE` | ✅ (у нас ещё и полный список — ➕) |
| `serialNumber` | `CERT_SN` | ✅ проверено |
| `signAlg` | `SIGNATURE_ALG` | ✅ проверено |
| `keyUser[]` (INDIVIDUAL/CEO/…) | маппинг роль-OID из `EXT_KEY_USAGE` | ✅ проверено (см. ниже) |
| `publicKey` (base64) | `PUBKEY` | ✅ проверено |
| `signature` (base64) | собств. разбор DER сертификата | ✅ (парсим сами; байты у нас есть) |
| `subject`, `issuer` | см. выше | ✅ |

### `keyUser` — маппинг ролей (эмпирически подтверждён на тестовых ключах)

| NCANode enum | EKU-OID | Проверено |
|--------------|---------|-----------|
| `INDIVIDUAL` | `1.2.398.3.3.4.1.1` | ✅ |
| `ORGANIZATION` | `1.2.398.3.3.4.1.2` (маркер ЮЛ) | ✅ |
| `CEO` (первый руководитель) | `1.2.398.3.3.4.1.2.1` | ✅ |
| `CAN_SIGN` (право подписи) | `1.2.398.3.3.4.1.2.2` | ✅ |
| `EMPLOYEE` (сотрудник) | `1.2.398.3.3.4.1.2.5` | ✅ |
| (инфосистема) | `1.2.398.3.3.4.1.2.6` | ✅ |
| (казначейство) | `1.2.398.5.19.1.2.2.1` | ✅ |
| `HR`, `CAN_SIGN_FINANCIAL`, `NCA_*`, `IDENTIFICATION*` | прочие OID НУЦ | ⚙️ по известной таблице OID |

### `CertificateRevocationStatus`

| NCANode | Наш источник | Статус |
|---------|--------------|--------|
| `revoked` | OCSP/CRL rc | ✅ проверено |
| `by` (OCSP/CRL) | тип проверки | ✅ |
| `revocationTime` | из OCSP-ответа | ✅ проверено (`Revocation Time`) |
| `reason` | из OCSP-ответа | ✅ проверено (`certificateHold`) |

### `CmsSignerInfo` / `TspInfo`

| NCANode | Наш источник | Статус |
|---------|--------------|--------|
| `signers[]` | перебор `sigId` (мультиподпись) | ✅ проверено (2 подписанта) |
| `certificates[]` | **у NCANode здесь только лист подписанта** (см. §5), не цепочка | ➕ мы отдаём полную цепочку |
| `tsp.genTime` | `KC_GetTimeFromSig` | ✅ |
| `tsp.serialNumber/policy/tsa/tspHashAlgorithm/hash` | разбор TSP-токена (RFC 3161) из CMS | ⚙️ парсим сами (токен у нас есть) |

---

## 3. Сверх NCANode (что мы отдаём, а они — нет)

- **Полный `keyUsage`/`extendedKeyUsage`** списком + все OID (NCANode схлопывает в
  `UNKNOWN/AUTH/SIGN`).
- **`authorityKeyIdentifier`, `subjectKeyIdentifier`, `certificatePolicies`** —
  в `CertificateInfo` NCANode их нет.
- **`businessCategory` (BC), `DC`** — у нас есть (напр. Казначейство), в
  `CertificateSubject` NCANode отсутствуют.
- **Сырой OCSP-ответ (base64), сырой `verifyInfo`, AIA/CRL-URL, признак CAdES-уровня,
  признак detached, восстановленное содержимое** — доступны.
- **Инфраструктура**: несколько транспортов (REST/gRPC/socket/MQ), пакетный и
  асинхронный режимы, observability — этого у NCANode нет.

---

## 3a. Как NCANode работает с цепочкой (по исходникам)

Разбор `kz.ncanode.service.CmsService`/`XmlService`/`CaService`:

- **NCANode НЕ извлекает цепочку из CMS/XML.** В `CmsSignerInfo.certificates`
  (`@Singular List`) кладётся только серт, совпадающий с **SID подписанта**
  (`certStore.getCertificates(signer.getSID())`) — то есть **лист**.
  `toCertificateInfo()` содержит поля только листа (`issuer` — DN-строка, не серт
  издателя). XML-`signers` — тоже листовые `CertificateInfo`.
- **Корень берётся не из подписи, а из отдельного доверенного CA-набора:**
  `CaService` скачивает CA по настроенным URL (`NCANODE_CA_URL`), кэширует на диск
  (`ca/*.cer`), обновляет по расписанию и проверяет по CRL;
  `getRootCertificateFor(cert)` ищет издателя по issuer-DN + проверке подписи.
  Используется только для **валидации** (`isValid`, OCSP/CRL) — в ответ не входит.

**Следствие:** «NCANode возвращает цепочку из CMS» — неверно; он возвращает лист и
валидирует его против скачанного CA-набора. **Мы отдаём больше** — полную цепочку
`signers[].chain` (лист из подписи + достройка из CA-источника/AIA, эмпирически
собрана пробником).

**Стоит перенять** их способ получать CA как ещё одну опцию CA-источника
(в дополнение к «bundle потребителя» и «AIA on-demand»): конфигурируемые URL →
скачать → кэш → рефреш по расписанию → CRL-проверка самих CA.

## 4. Разрывы и оценка усилий

| Возможность | Есть в Kalkan-C-API? | Как реализуем | Усилие |
|-------------|----------------------|---------------|--------|
| `signature` сертификата (байты) | нет свойства | свой разбор DER (байты сертификата у нас есть) | низкое |
| Полный `TspInfo` (policy/tsa/hash/serial) | только время (`KC_GetTimeFromSig`) | разбор TSP-токена RFC 3161 из CMS | среднее |
| `gender` | нет | вывод из ИИН | тривиально |
| Полный `keyUser`-enum | частично (EKU-OID) | таблица OID НУЦ | низкое |
| **PDF** sign/verify | **нет** | PDF-слой (напр. pdfcpu/UniPDF) + Kalkan для хеша/подписи | **высокое** |
| **JWT** encode/decode (GOST) | нет | сами (header.payload → `SignHash` → base64url) | среднее |

**Вывод.** Паритет полей — **полный** (мы не отдаём меньше, по метаданным
сертификата — больше). Из функциональности единственный реально трудозатратный
пункт — **PDF-подпись** (её нет в криптоядре; NCANode делает её отдельным Java-
слоем, нам нужен аналог на Go). JWT — несложно. Всё остальное — тот же Kalkan,
те же или более полные данные, что подтверждено пробником.
