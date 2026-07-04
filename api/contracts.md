# Драфт JSON-контрактов qoltanba (v1)

JSON-зеркало `api/qoltanba-draft.proto` для REST / Unix-socket / CLI / MQ. Значения в
примерах — из реальных прогонов пробника (`tools/probe`). Это **драфт**: составы
полей уточняются вместе с остальными нюансами. Паритет с NCANode v3 + наши
«сверх-поля» помечены `// +`.

## Соглашения

- **Кодировки:** бинарные поля — base64; сертификаты — PEM/DER (`encoding`).
- **Время:** RFC3339 (`2026-05-08T06:45:13Z`); исходный формат либы
  `DD.MM.YYYY HH:MM:SS ±HH:MM` нормализуется.
- **Секреты** (`password`, `pin`, inline `p12`) — только во входе, никогда в
  ответах/логах/метриках/трейсах.
- **Best-effort извлечение:** недоступное поле → `null` + запись в `warnings`
  (`{field, reason}`), а не отказ всей операции.
- **Ошибка криптоядра:** `libError = { code: "0x08F0001C", text: "..." }` или `null`.
- **Async для больших файлов:** `data` может быть `{ "filePath": ... }` или
  `{ "url": ... }` вместо inline base64.

---

## Общий тип: `certificate`

```jsonc
{
  "valid": true,
  "notBefore": "2026-05-08T06:45:13Z",
  "notAfter":  "2027-05-08T06:45:13Z",
  "serialNumber": "6C425659BD2FC6DC587B871AEDE1857727CF8451",
  "signAlg": "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)",
  "keyUsage": "SIGN",                         // упрощённо (паритет NCANode)
  "keyUser": ["INDIVIDUAL"],                  // роли из EKU-OID
  "publicKey": "MIGsMCMGCSqDDgMK…",           // base64 DER
  "signature": "…",                           // base64, парсим из DER
  "subject": {
    "commonName": "ТЕСТОВ ТЕСТ",
    "lastName": "ТЕСТОВ", "surName": "ТЕСТОВИЧ",
    "iin": "123456789011", "bin": null,
    "gender": "MALE",                         // выводим из ИИН
    "organization": null, "email": null,
    "country": "KZ", "locality": null, "state": null,
    "dn": "CN=ТЕСТОВ ТЕСТ,SN=ТЕСТОВ,serialNumber=IIN123456789011,C=KZ,GN=ТЕСТОВИЧ",
    "businessCategory": null,                 // +
    "domainComponent": null                   // +
  },
  "issuer": { "commonName": "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) TEST 2022", "country": "KZ", "dn": "…" },
  "revocations": [
    { "revoked": false, "by": "OCSP", "revocationTime": null, "reason": null,
      "checkedAt": "2026-07-04T10:00:00Z", "ocspResponse": "MIIF…" }   // + сырой OCSP
  ],

  // + сверх NCANode:
  "ownerType": "OWNER_INDIVIDUAL",
  "keyUsageList": ["digitalSignature","nonRepudiation","keyAgreement"],
  "extendedKeyUsage": ["E-mail Protection (1.3.6.1.5.5.7.3.4)","1.2.398.3.3.4.1.1"],
  "signAlgOid": "1.2.398.3.10.1.1.2.3.2",
  "publicKeyAlgorithm": "gost2015-512",
  "authorityKeyId": "FAD24B1BA3A0C961FE1CA8503E6AA2BB450DB8A3",
  "subjectKeyId": "EC425659BD2FC6DC587B871AEDE1857727CF8451",
  "policyOids": ["1.2.398.3.3.2"],
  "caIssuerUrls": ["http://test.pki.gov.kz/cert/nca_gost2022_test.cer"],
  "ocspUrls": ["http://test.pki.gov.kz/ocsp/"],
  "crlUrls": ["http://test.pki.gov.kz/crl/nca_gost2022_test.crl"],
  "pem": "-----BEGIN CERTIFICATE-----…"
}
```

Для **отозванного** серта `revocations[0]` = `{ "revoked": true, "by": "OCSP",
"revocationTime": "2026-07-03T20:37:07Z", "reason": "certificateHold" }`.

---

## `POST /verify` (CMS/XML/WSSE)

**Запрос:**
```jsonc
{
  "format": "CMS",
  "signature": { "bytesValue": "<base64 CMS>", "encoding": "BASE64" },
  "data":      null,                       // для detached — исходные данные
  "options": {
    "revocationCheck": ["OCSP"],
    "extractContent": true,                // + вернуть оригинал (attached)
    "buildChain": true, "fetchAia": true,  // + достроить цепочку (CA/AIA)
    "caCerts": []
  }
}
```

**Ответ** (мультиподпись — оба подписанта, из реального прогона):
```jsonc
{
  "valid": true,
  "format": "CMS",
  "signatureCount": 2,
  "signers": [
    {
      "index": 1,
      "certificate": { "serialNumber": "303E…BBE4E",
        "subject": { "commonName": "ТЕСТОВ ТЕСТ", "iin": "123456789011",
                     "bin": "123456789021", "organization": "АО \"ТЕСТ\"" },
        "keyUser": ["CEO"] },                        // первый руководитель
      "chain": [ { "…leaf…": {} }, { "…НУЦ…": {} }, { "…КУЦ…": {} } ],
      "chainComplete": true, "trustAnchorFound": true,   // +
      "valid": true,
      "signingTime": "2026-07-04T10:00:01Z",
      "tsp": null,
      "cadesLevel": "CADES_BES",                          // +
      "verifyInfo": "Signature N 1\nId = 1\n…"            // + сырой
    },
    {
      "index": 2,
      "certificate": { "serialNumber": "…857727CF8451",
        "subject": { "commonName": "ТЕСТОВ ТЕСТ", "iin": "123456789011" },
        "keyUser": ["INDIVIDUAL"] },                      // физлицо
      "valid": true
    }
  ],
  "detached": false,                                       // +
  "content": "SGVsbG8sI...",                               // + оригинал (base64)
  "warnings": [ { "field": "signers[1].issuer.email", "reason": "KCR_GETCERTPROPERR" } ],
  "libError": null
}
```

> Нюанс (проверено): индекс `sigId` ≠ порядок подписания и различается CMS/XML —
> порядок не нести смыслом, использовать `signingTime`/идентичность серта.

---

## `POST /sign` и `POST /sign/add`

**Запрос `/sign`:**
```jsonc
{
  "format": "CMS",
  "data": { "bytesValue": "<base64 данных>", "encoding": "BASE64" },
  "key":  { "inline": { "p12": "<base64 .p12>", "password": "***" } },
  "options": {
    "detached": false, "withTsp": false,
    "tsaPolicy": "TSA_GOST2015_POLICY", "tsaUrl": "http://test.pki.gov.kz/tsp/",
    "outputEncoding": "PEM", "noCheckCertTime": false
  }
}
```
**Ответ:** `{ "signature": "-----BEGIN CMS-----…", "format": "CMS", "libError": null }`

**`/sign/add`** (со-подпись): как `/sign`, но с полем `signature` = существующий
контейнер, к которому добавляется подпись ключом `key`.

---

## `POST /cert/info` и `POST /cert/validate`

```jsonc
// /cert/info
{ "certificate": { "bytesValue": "<PEM/DER base64>", "encoding": "PEM" },
  "buildChain": true, "fetchAia": true, "revocationCheck": ["OCSP"] }
// -> { "certificate": {…}, "chain": [ leaf, НУЦ, КУЦ ], "warnings": [], "libError": null }

// /cert/validate
{ "certificate": {…}, "method": "OCSP" }
// -> { "valid": true, "revocations": [ {revoked:false, by:"OCSP", …} ], "info": "OCSP: … good", "libError": null }
```

## `POST /extract`
```jsonc
{ "signature": { "bytesValue": "<base64 CMS>", "encoding": "BASE64" } }
// -> { "content": "SGVsbG8s…", "detached": false, "libError": null }
```

---

## Пакетный режим (N8)

```jsonc
// POST /verify/batch
{ "items": [ {…VerifyRequest…}, {…} ], "policy": "BATCH_CONTINUE_ON_ERROR" }
// -> { "total": 2, "succeeded": 2, "failed": 0, "results": [ {…VerifyResponse…}, {…} ] }
```

## Асинхронные задания (N9)

```jsonc
// POST /jobs
{ "verify": {…VerifyRequest с data.url…}, "callbackUrl": "https://…", "correlationId": "abc" }
// -> { "jobId": "j_123" }
// GET /jobs/j_123
{ "jobId": "j_123", "state": "SUCCEEDED", "progress": 100,
  "correlationId": "abc", "verifyResult": {…} }
```

---

## Соответствие NCANode v3

Все поля их схем (`CertificateSubject`, `CertificateInfo`, `CertificateRevocationStatus`,
`CmsSignerInfo`, `TspInfo`, verify-ответы) присутствуют здесь под теми же смыслами;
детали и «сверх-поля» — в [`docs/COMPARISON-ncanode.md`](../docs/COMPARISON-ncanode.md).
Отличия имён (`camelCase` в JSON ↔ `snake_case` в proto) — косметические.
