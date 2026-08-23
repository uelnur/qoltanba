# Задача: ключи и сертификаты (открыть, экспортировать, разобрать, валидировать)

Самодостаточно для работы с ключом/сертификатом через Kalkan C-API — функции,
нужные флаги, рецепты и подводные камни в одном месте. Соглашения вызова (буфер+len,
NUL-обрезка, `rc==0`) — в [`index.md`](index.md); загрузка либы — [`loading.md`](loading.md);
исчерпывающие таблицы значений — [`reference.md`](reference.md). Подпись/проверка —
[`signing.md`](signing.md).

## Функции

```c
unsigned long KC_LoadKeyStore(int storage, char *password, int passLen,
                              char *container, int containerLen, char *alias);
unsigned long KC_GetTokens(unsigned long storage, char *tokens, unsigned long *tk_count);
unsigned long KC_GetCertificatesList(char *certificates, unsigned long *cert_count);
unsigned long X509ExportCertificateFromStore(char *alias, int flag, char *outCert, int *outCertLength);
unsigned long X509LoadCertificateFromFile(char *certPath, int certType);
unsigned long X509LoadCertificateFromBuffer(unsigned char *inCert, int certLength, int flag);
unsigned long X509CertificateGetInfo(char *inCert, int inCertLength, int propId,
                                     unsigned char *outData, int *outDataLength);
unsigned long X509ValidateCertificate(char *inCert, int inCertLength, int validType,
                                      char *validPath, long long checkTime,
                                      char *outInfo, int *outInfoLength, int flag,
                                      char *getOCSPResponse, int *getOCSPResponseLenght);
```

## Открыть ключ (`KC_LoadKeyStore`)

- `storage` — тип хранилища: `KCST_PKCS12` (0x1) для `.p12`/`.pfx`, либо токен
  (`KCST_KAZTOKEN`, `KCST_KZIDCARD`, `KCST_JACARTA`, `KCST_ETOKEN72K`,
  `KCST_ETOKEN5110`, `KCST_AKEY`) — полный список в [`reference.md`](reference.md).
- Для **PKCS12** `container` = **путь к файлу** (`.p12`), `containerLen` = длина
  пути — либа читает файл сама. `password`/`passLen` — пароль контейнера.
- `alias` — выходной буфер (заранее обнули `alias[0]=0`). На тестовых ключах НУЦ
  возвращается **пустым** → в подпись/verify передавать пустой alias `""`.
- Неверный пароль → `KCR_INVALIDPASSWORD`. Переключение на другой ключ — повторный
  `KC_LoadKeyStore`.

## Экспорт сертификата владельца

`X509ExportCertificateFromStore(alias, flag, out, &outLen)` — `flag` — формат вывода:
`KC_CERT_PEM` (0x102), `KC_CERT_DER` (0x101), `KC_CERT_B64` (0x104).

## Разбор сертификата (`X509CertificateGetInfo`)

**Одно свойство за вызов**, `propId` из `KC_CERTPROP_*`. Полный разбор = цикл по
всем `propId`. Значение — UTF-8 строка **`имя=значение`**, NUL-терминирована в
дополненном буфере → срезать префикс `имя=` и резать по первому `\x00`.

- **Свойства нет** → `KCR_GETCERTPROPERR` (`0x08F00038`) — **норма** (у профиля нет
  поля), не ошибка операции.
- **SIGSEGV-ловушка:** разбирай выход только при `rc==0 && 0 < outLen < cap`; на
  битом/пустом серте либа падает.

Свойства (значения `propId` — в [`reference.md`](reference.md)); форматы значений:

| Свойство | Пример | Формат |
|----------|--------|--------|
| `SUBJECT_DN` / `ISSUER_DN` | `CN = …, serialNumber = IIN…, C = KZ` | агрегат RDN, разделитель `, ` |
| `SUBJECT_SERIALNUMBER` | `serialNumber=IIN123456789011` | ИИН как `IIN<12>` |
| `SUBJECT_ORGUNIT_NAME` | `OU=BIN123456789021` | у ЮЛ несёт БИН как `BIN<12>` |
| `NOTBEFORE`/`NOTAFTER` | `notBefore=08.05.2026 06:45:13 +00:00` | `DD.MM.YYYY HH:MM:SS ±HH:MM` |
| `CERT_SN`/`AUTH_KEY_ID`/`SUBJ_KEY_ID` | `…=6C4256…` | HEX (верхний регистр) |
| `KEY_USAGE` | `keyUsage=digitalSignature nonRepudiation keyAgreement` | через пробел |
| `EXT_KEY_USAGE` | `extendedKeyUsage=…; 1.2.398.3.3.4.1.1 (…)` | человекочит.+OID, разделитель `; ` |
| `SIGNATURE_ALG` | `signatureAlgorithm=GOST R 34.10-2015 … (OID)` | текст + OID |
| `PUBKEY` | `MIGsMCMG…` | base64 DER (SubjectPublicKeyInfo) |
| `POLICIES_ID` | `certificatePolicies=1.2.398.3.3.2` | OID(ы) |

Различия по профилям (ФЛ/ЮЛ/ИС), роль по OID в `EXT_KEY_USAGE`, вывод
ИИН/БИН/пола/ownerType — доменная логика, см. [`../nuc-pki-reference.md`](../nuc-pki-reference.md).

## Валидация (`X509ValidateCertificate`)

Сначала загрузи CA в доверенный набор либы:
`X509LoadCertificateFromFile(path, KC_CERT_CA)` для корня и
`…KC_CERT_INTERMEDIATE` для промежуточного.

Затем: `validType` = `KC_USE_OCSP` (0x404) / `KC_USE_CRL` (0x402); `validPath` = URL
OCSP или путь к `.crl`; `checkTime` = Unix-время (сек) точки проверки; `flag` =
`KC_GET_OCSP_RESPONSE` (0x80000) — вернуть сырой OCSP-ответ в `getOCSPResponse`.

- **OCSP** (сетевой): rc `0` = **good**, rc `1` = **revoked** (это **не**
  `KCR_CERT_STATUS_*`). Статус — из rc **и** текста `outInfo` (`OCSP: … status: good
  … This Update … Next Update …` / `… revoked … Reason: certificateHold …
  Revocation Time …`). При `KC_GET_OCSP_RESPONSE` — base64 ответа (~6.4 КБ).
- **CRL** (офлайн, файл): печатает цепочку/данные в `outInfo`; в офлайн-прогоне
  вернул нестандартный `0x08F0005D` (устаревший CRL). Для надёжного статуса
  предпочтителен OCSP. **`validPath` = путь к файлу** → CRL можно скачать/обновлять
  своим слоем и отдать библиотеке готовый файл (она проверит подпись CRL и статус).

**Сетевая связанность OCSP (эмпирически по таблице функций).** Отдельного примитива
«проверить *данный* OCSP-ответ» в API нет: единственная точка — `X509ValidateCertificate`
(`KC_USE_OCSP`), которая **сама ходит в сеть** (модуль `Kalkan_X509OCSP.c`); `getOCSPResponse`
— **только выход**. OpenSSL-функции OCSP-верификации внутри `libkalkancrypto` **не
экспортированы**. Значит own-fetch+library-verify возможен для **CRL** (файловый режим),
но **не для OCSP**. Verify наружу — только для контейнеров (`VerifyData` CMS, `VerifyXML`
XML, `ZipConVerify` ZIP); «verify GOST-подписи над произвольными байтами» — нет.

**Прокси (`KC_SetProxy`).** Сетевые обращения (OCSP/AIA/TSA/дозагрузка CA) идут через
внутренний HTTP либы; управляется:
```c
KC_SetProxy(int flags, char *inProxyAddr, char *inProxyPort, char *inUser, char *inPass)
```
`flags` = `KC_PROXY_ON` (0x2000) [| `KC_PROXY_AUTH` (0x4000)] / `KC_PROXY_OFF` (0x1000).
Глобально на экземпляр (как `KC_TSASetUrl`). **Таймаут/retry/backoff внутреннего HTTP
не настраиваются** — только исход `KCR_OCSP_CONNECTIONERR` (`+0x31`).

## Рецепт: построение цепочки

**Единого вызова `[leaf, intermediate, root]` нет.** В подписи вложен только лист.
Достраивать:

1. Загрузить CA-файлы (`X509LoadCertificateFromFile`) → `X509ValidateCertificate`
   печатает цепочку в `outInfo`; **или**
2. По **AIA**: в DER листа найти URL `CA Issuers` (регэксп по `…\.cer`), скачать
   издателя по HTTP, разобрать `X509CertificateGetInfo`, повторять вверх, пока есть
   ссылка (у корня её нет). Нюанс: AIA промежуточного может вести на **другой хост**
   (`root.gov.kz`). В проде: таймауты, лимит переходов, кэш, доверие только якорю
   из trust-store.

Порядок — по `AUTH_KEY_ID` листа = `SUBJ_KEY_ID` издателя; корень самоподписан
(`SUBJECT_DN == ISSUER_DN`). **Признак CA-уровня:** `keyUsage=keyCertSign cRLSign` +
**нет** `EXT_KEY_USAGE` (`KCR_GETCERTPROPERR`); у листа — наоборот.

Достройка по AIA (без локальных CA — только сеть):

```go
// URL издателя из DER листа: ссылка AIA "CA Issuers" оканчивается на .cer
var aiaRe = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+\.cer`)

func aiaWalk(leafDER []byte) [][]byte {           // → цепочка DER: leaf, НУЦ, КУЦ…
    var chain [][]byte
    cur := leafDER
    for hop := 0; hop < 6; hop++ {                // лимит переходов — защита
        m := aiaRe.Find(cur)
        if m == nil { break }                     // ссылки нет → достигнут корень
        body, err := httpGet(string(m))           // таймаут обязателен
        if err != nil { break }
        chain = append(chain, body)
        cur = body                                // разбор — X509CertificateGetInfo
    }
    return chain
}
```

Упорядочивание набора сертов в цепочку — по `SUBJ_KEY_ID`(издатель) ↔
`AUTH_KEY_ID`(субъект): старт с листа (его `SUBJ_KEY_ID` никто не указывает в своём
`AUTH_KEY_ID`), затем по каждому шагу ищи серт, чей `SUBJ_KEY_ID` == `AUTH_KEY_ID`
текущего, пока `AUTH_KEY_ID` пуст или равен `SUBJ_KEY_ID` (корень).
