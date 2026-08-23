# Справочник значений: константы и коды ошибок

Приложение к `kalkan-api` — открывать, когда нужно конкретное значение. Всё дословно
из `KalkanCrypt.h`. Семантика и связки — в [`certificates.md`](certificates.md) /
[`signing.md`](signing.md); ориентир — [`index.md`](index.md).

## Типы хранилищ ключей (`KC_LoadKeyStore` / `KC_GetTokens`, `storage`)

| Константа | Значение | Хранилище |
|-----------|----------|-----------|
| `KCST_PKCS12` | `0x00000001` | файл `.p12`/`.pfx` |
| `KCST_KZIDCARD` | `0x00000002` | удостоверение личности РК |
| `KCST_KAZTOKEN` | `0x00000004` | KAZTOKEN |
| `KCST_ETOKEN72K` | `0x00000008` | eToken 72K |
| `KCST_JACARTA` | `0x00000010` | JaCarta |
| `KCST_X509CERT` | `0x00000020` | X509-сертификат |
| `KCST_AKEY` | `0x00000040` | aKey |
| `KCST_ETOKEN5110` | `0x00000080` | eToken 5110 |

## Формат сертификата (`X509ExportCertificateFromStore`, `flag`)

`KC_CERT_DER` `0x00000101` · `KC_CERT_PEM` `0x00000102` · `KC_CERT_B64` `0x00000104`

## Тип загружаемого CA (`X509LoadCertificateFromFile`, `certType`)

`KC_CERT_CA` `0x00000201` (корень) · `KC_CERT_INTERMEDIATE` `0x00000202`
(промежуточный) · `KC_CERT_USER` `0x00000204`

## Тип валидации (`X509ValidateCertificate`, `validType`)

`KC_USE_NOTHING` `0x00000401` · `KC_USE_CRL` `0x00000402` · `KC_USE_OCSP` `0x00000404`

## Канонизация XML (C14N)

Для подписи: `KC_XML_INCL_C14N` `0x01000001`, `KC_XML_INCL_C14NCOMMENT` `0x01000002`,
`KC_XML_INCL_C14N11` `0x01000004`, `KC_XML_INCL_C14N11COMMENT` `0x01000008`,
`KC_XML_EXCL_C14N` `0x01000010`, `KC_XML_EXCL_C14NCOMMENT` `0x01000020`.
Для контента (`KC_XMLC_*`): те же режимы, `0x01000040`…`0x01000800`.

## Флаги операций (`SignData`/`VerifyData`/`SignXML`/…)

| Константа | Значение | Смысл |
|-----------|----------|-------|
| `KC_SIGN_DRAFT` | `0x00000001` | черновой формат подписи |
| `KC_SIGN_CMS` | `0x00000002` | CMS/PKCS#7 |
| `KC_IN_PEM` | `0x00000004` | вход — PEM |
| `KC_IN_DER` | `0x00000008` | вход — DER |
| `KC_IN_BASE64` | `0x00000010` | вход — base64 |
| `KC_IN2_BASE64` | `0x00000020` | второй вход — base64 |
| `KC_DETACHED_DATA` | `0x00000040` | открепить контент |
| `KC_WITH_CERT` | `0x00000080` | вложить сертификат |
| `KC_WITH_TIMESTAMP` | `0x00000100` | метка времени TSA |
| `KC_OUT_PEM` | `0x00000200` | выход — PEM |
| `KC_OUT_DER` | `0x00000400` | выход — DER |
| `KC_OUT_BASE64` | `0x00000800` | выход — base64 |
| `KC_PROXY_OFF` | `0x00001000` | прокси выкл |
| `KC_PROXY_ON` | `0x00002000` | прокси вкл |
| `KC_PROXY_AUTH` | `0x00004000` | прокси с авторизацией |
| `KC_IN_FILE` | `0x00008000` | вход — путь к файлу |
| `KC_NOCHECKCERTTIME` | `0x00010000` | не сверять срок серта |
| `KC_HASH_SHA256` | `0x00020000` | хеш SHA-256 |
| `KC_HASH_GOST95` | `0x00040000` | хеш ГОСТ-95 |
| `KC_GET_OCSP_RESPONSE` | `0x00080000` | вернуть сырой OCSP-ответ |

## Свойства сертификата (`X509CertificateGetInfo`, `propId`)

| propId | Свойство | propId | Свойство |
|--------|----------|--------|----------|
| `0x0801` | ISSUER_COUNTRYNAME | `0x0810` | SUBJECT_ORGUNIT_NAME (БИН у ЮЛ) |
| `0x0802` | ISSUER_SOPN | `0x0811` | SUBJECT_BC (businessCategory) |
| `0x0803` | ISSUER_LOCALITYNAME | `0x0812` | SUBJECT_DC |
| `0x0804` | ISSUER_ORG_NAME | `0x0813` | NOTBEFORE |
| `0x0805` | ISSUER_ORGUNIT_NAME | `0x0814` | NOTAFTER |
| `0x0806` | ISSUER_COMMONNAME | `0x0815` | KEY_USAGE |
| `0x0807` | SUBJECT_COUNTRYNAME | `0x0816` | EXT_KEY_USAGE (роль-OID) |
| `0x0808` | SUBJECT_SOPN | `0x0817` | AUTH_KEY_ID |
| `0x0809` | SUBJECT_LOCALITYNAME | `0x0818` | SUBJ_KEY_ID |
| `0x080a` | SUBJECT_COMMONNAME | `0x0819` | CERT_SN |
| `0x080b` | SUBJECT_GIVENNAME | `0x081a` | ISSUER_DN |
| `0x080c` | SUBJECT_SURNAME | `0x081b` | SUBJECT_DN |
| `0x080d` | SUBJECT_SERIALNUMBER (ИИН) | `0x081c` | SIGNATURE_ALG |
| `0x080e` | SUBJECT_EMAIL | `0x081d` | PUBKEY |
| `0x080f` | SUBJECT_ORG_NAME | `0x081e` | POLICIES_ID |

## Коды возврата `KCR_*`

`KCR_OK` = `0x00000000`. Все прочие = `KCR_BASE` (`0x08F00000`) + смещение ниже
(итоговый код = `0x08F0____`). Помечены `⚑` — наблюдались эмпирически.

| Смещение | Код | Значение |
|----------|-----|----------|
| `+0x01` | KCR_INIT_ERROR | ошибка `KC_Init` |
| `+0x02`/`+0x03` | KCR_ERROR_READ/OPEN_PKCS12 | чтение/открытие PKCS12 |
| `+0x05` | KCR_BUFFER_TOO_SMALL | мал выходной буфер |
| `+0x06` | KCR_CERT_PARSE_ERROR | разбор сертификата |
| `+0x07` | KCR_INVALID_FLAG | неверный флаг |
| `+0x09` | KCR_INVALIDPASSWORD | неверный пароль контейнера |
| `+0x0a`/`+0x0b` | KCR_CERTWRONGDATE / KCR_CERTEXPIRED | даты серта |
| `+0x0c` | KCR_ISNOTCACERT | серт не CA |
| `+0x0e` | KCR_CHECKCHAINERROR | ошибка цепочки |
| `+0x16` | KCR_KEYNOTFOUND | ключ не найден |
| `+0x1b` | KCR_CERTNOTFOUND | сертификат не найден |
| `+0x1c` ⚑ | KCR_VERIFYSIGNERROR | ошибка проверки подписи |
| `+0x1e` | KCR_UNKNOWN_CMS_FORMAT | неизвестный формат CMS |
| `+0x20` | KCR_CA_CERT_NOT_FOUND | нет CA-сертификата |
| `+0x22` ⚑ | KCR_LOADTRUSTEDCERTSERR | не загружены доверенные CA (verify мультиподписи XML) |
| `+0x24` | KCR_NOSIGNFOUND | подпись не найдена |
| `+0x26` | KCR_XMLPARSEERROR | разбор XML |
| `+0x30`/`+0x31` | KCR_OCSP_REQERR / CONNECTIONERR | OCSP-запрос/соединение |
| `+0x38` ⚑ | KCR_GETCERTPROPERR | **свойства нет** (норма → `null`) |
| `+0x39` ⚑ | KCR_SIGNFORMMAT | несовпадение флагов sign/verify |
| `+0x3a`/`+0x3b` | KCR_INDATAFORMAT / OUTDATAFORMAT | формат входа/выхода |
| `+0x42` ⚑ | KCR_CERTTIMEINVALID | срок серта (нет `KC_NOCHECKCERTTIME`) |
| `+0x44` | KCR_TSACREATEQUERY | ошибка TSA-запроса |
| `+0x47` | KCR_HTTPERROR | HTTP-ошибка (сеть) |
| `+0x48`/`+0x49` | KCR_CADESBES/CADEST_FAILED | уровень CAdES BES/T |
| `+0x4a` ⚑ | KCR_NOTSATOKEN | в подписи нет TSP-токена |
| `+0x50` | KCR_FILEREADERROR | чтение файла |
| `+0x52`/`+0x53` | KCR_ZIPEXTRACTERR / NOMANIFESTFILE | ZIP |
| `+0x101` | KCR_LIBRARYNOTINITIALIZED | не вызван `KC_Init` |
| `+0x200` | KCR_ENGINELOADERR | загрузка движка |
| `+0x300` | KCR_PARAM_ERROR | ошибка параметра |
| `+0x400`/`+0x401`/`+0x402` | KCR_CERT_STATUS_OK/REVOKED/UNKNOWN | статус серта |

Полный список смещений (там, где не перечислены) — в `KalkanCrypt.h` (блок
`#define KCR_*`). Наблюдённый вне заголовка код: **`0x08F0005D`** — офлайн-CRL
(вероятно устаревший/неполный), нестандартный.

> **Внимание к OCSP:** `X509ValidateCertificate` по OCSP возвращает не
> `KCR_CERT_STATUS_*`, а **`0` (good) / `1` (revoked)** — читать rc **и** текст
> `outInfo`.
