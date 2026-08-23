# Задача: подпись и проверка (CMS, XML, WSSE, ZIP)

Самодостаточно для подписи/проверки через Kalkan C-API — функции, флаги, рецепты и
подводные камни. Соглашения вызова — [`index.md`](index.md); открыть ключ (нужно
перед подписью) — [`certificates.md`](certificates.md); исчерпывающие таблицы —
[`reference.md`](reference.md).

## Функции

```c
unsigned long SignData(char *alias, int flags, char *inData, int inDataLength,
                       unsigned char *inSign, int inSignLen,
                       unsigned char *outSign, int *outSignLength);
unsigned long VerifyData(char *alias, int flags, char *inData, int inDataLength,
                         unsigned char *inoutSign, int inoutSignLength,
                         char *outData, int *outDataLen,
                         char *outVerifyInfo, int *outVerifyInfoLen,
                         int inCertID, char *outCert, int *outCertLength);
unsigned long UVerifyData(/* та же сигнатура, что VerifyData; из поздних версий */);
unsigned long SignXML(char *alias, int flags, char *inData, int inDataLength,
                      unsigned char *outSign, int *outSignLength,
                      char *signNodeId, char *parentSignNode, char *parentNameSpace);
unsigned long VerifyXML(char *alias, int flags, char *inData, int inDataLength,
                        char *outVerifyInfo, int *outVerifyInfoLen);
unsigned long SignWSSE(char *alias, unsigned long flags, char *inData, int inDataLength,
                       unsigned char *outSign, int *outSignLength, char *signNodeId);
unsigned long ZipConSign(char *alias, const char *filePath, const char *name,
                         const char *outDir, int flags);
unsigned long ZipConVerify(char *inZipFile, int flags, char *outVerifyInfo, int *outVerifyInfoLen);
unsigned long HashData(char *algorithm, int flags, char *inData, int inDataLength,
                       unsigned char *outData, int *outDataLength);
unsigned long SignHash(char *alias, int flags, char *inHash, int inHashLength,
                       unsigned char *outSign, int *outSignLength);
unsigned long KC_GetCertFromCMS(char *inCMS, int inCMSLen, int inSignId, int flags,
                                char *outCert, int *outCertLength);
unsigned long KC_getCertFromXML(const char *inXML, int inXMLLength, int inSignID,
                                char *outCert, int *outCertLength);
unsigned long KC_getSigAlgFromXML(const char *xml, int len, char *retSigAlg, int *retLen);
unsigned long KC_GetTimeFromSig(char *inData, int inDataLength, int flags,
                                int inSigId, time_t *outDateTime);
void          KC_TSASetUrl(char *tsaurl);
```

## Флаги операций (комбинируются побитово)

Формат подписи: `KC_SIGN_CMS` (0x2) — CMS/PKCS#7; `KC_SIGN_DRAFT` (0x1).
Кодировка входа: `KC_IN_PEM` (0x4) / `KC_IN_DER` (0x8) / `KC_IN_BASE64` (0x10) /
`KC_IN_FILE` (0x8000, `inData` = путь).
Кодировка выхода: `KC_OUT_PEM` (0x200) / `KC_OUT_DER` (0x400) / `KC_OUT_BASE64` (0x800).
Прочее: `KC_DETACHED_DATA` (0x40) — открепить контент; `KC_WITH_TIMESTAMP` (0x100) —
метка времени TSA; `KC_WITH_CERT` (0x80) — вложить серт; **`KC_NOCHECKCERTTIME`
(0x10000)** — не сверять срок с системными часами. Полный список — [`reference.md`](reference.md).

> **Правило:** verify зовётся **с теми же флагами**, что и подпись, — иначе
> `0x08F00039` (`KCR_SIGNFORMMAT`). Успех — по `rc==0`, не по тексту `outVerifyInfo`
> (там даже при успехе `error:00000000:...`).

## Рецепт: подпись CMS

```
alias = open key (certificates.md)
flags = KC_SIGN_CMS | KC_OUT_PEM | KC_NOCHECKCERTTIME        // [ | KC_DETACHED_DATA ]
SignData(alias, flags, data, len, NULL, 0, out, &outLen)     // inSign=NULL для первой
→ out = PEM-блок -----BEGIN CMS-----…
```

Без `KC_NOCHECKCERTTIME` при истёкшем/будущем серте → `0x08F00042`
(`KCR_CERTTIMEINVALID`). **Тот же код 0x08F00042** приходит и для *валидного* серта,
если проверка времени включена, а цепочка не построена — библиотека якорит
подписанта к доверенному корню, поэтому CA (корень + промежуточные) должны быть
**загружены в store до подписи** (`X509LoadCertificateFromFile`), иначе текст
«Load certificate from system store — failed to load root or intermediate
certificate». Leaf-only p12 сам по себе не проходит.

- **CMS-выход только PEM.** `SignData` для CMS выдаёт валидный результат лишь с
  `KC_OUT_PEM`; без него (или с `KC_OUT_DER`) — пустой/усечённый blob при `rc==0`.
  Нужен DER — снять PEM-обёртку постобработкой (`VerifyData` принимает и DER, и PEM).
- **Пустой выход при `rc==0` — сигнал.** Кроме DER, так проявляется таймстамп к
  чужому TSA (см. ниже): проверяй длину, не только код возврата.

## Рецепт: проверка CMS + извлечение подписанта

```
VerifyData("", sameFlags, data, len, cms, cmsLen,
           outData,&,  outVerifyInfo,&,  inCertID=0, outCert,&)
→ rc==0 = валидно; outCert = серт подписанта (inCertID 0-based) → X509CertificateGetInfo
```

## Рецепт: восстановить оригинальный контент (attached-CMS)

```
VerifyData("", KC_SIGN_CMS|KC_IN_PEM|KC_NOCHECKCERTTIME,
           inData=NULL, 0, cms, cmsLen, outData,&, …)         // БЕЗ KC_OUT_PEM
→ outData = исходные байты
```

- **Без `KC_OUT_PEM`** — иначе либа обернёт контент в PEM и отдаст пусто.
- Работает только для **attached** (без `KC_DETACHED_DATA`). Для detached контента
  в подписи нет — оригинал подавать в `inData` отдельно.

## Рецепт: множественная подпись (co-sign)

```
SignData(aliasB, KC_SIGN_CMS|KC_IN_PEM|KC_OUT_PEM|…, data, len,
         inSign=cmsA, inSignLen, out, &outLen)                // добавляет signerInfo B
```

- Переключить ключ подписанта B — повторный `KC_LoadKeyStore`.
- Все подписанты: перебор `KC_GetCertFromCMS(cms, len, sigId, KC_IN_PEM|KC_OUT_PEM, …)`,
  `sigId` **1-based** (стоп, когда очередной подписи нет).
- **Ловушка индекса:** `sigId` ≠ порядок подписания и различается CMS/XML (в CMS
  `#1` = последний добавленный). Смысл к индексу не привязывать.

## Рецепт: XML sign / verify / extract

```
SignXML(alias, KC_NOCHECKCERTTIME, xml, len, out,&, "", "", "")   // узлы пустые → весь документ
VerifyXML("", KC_NOCHECKCERTTIME, signedXml, len, outVerifyInfo,&) // per-signature инфо
KC_getSigAlgFromXML(signedXml, len, out,&)                        // строка алгоритма
KC_getCertFromXML(signedXml, len, sigId=1, out,&)                 // серт подписанта (1-based)
```

- Co-sign XML — повторный `SignXML` над уже подписанным (добавляется второй
  `<Signature>`).
- Verify **мультиподписи** XML требует загруженных доверенных CA
  (`X509LoadCertificateFromFile`), иначе `0x08F00022` (`KCR_LOADTRUSTEDCERTSERR`).
  Извлечение подписантов от этого не зависит.
- WSSE — `SignWSSE(alias, flags, data, len, out,&, signNodeId)`, проверка через
  `VerifyXML` (+доверенные CA). **Подписываемый узел обязан нести `wsu:Id`, а
  `signNodeId` — ссылаться на него**, иначе `0x08F00033` («ID attribute is not
  found»). Проверено: `<soap:Body wsu:Id="body-1">` + `signNodeId="body-1"`.

## Рецепт: метка времени

```
KC_TSASetUrl("http://test.pki.gov.kz/tsp/")     // до подписи
SignData(..., flags | KC_WITH_TIMESTAMP, ...)
KC_GetTimeFromSig(cms, len, KC_IN_PEM, inSigId, &t)   // t = time_t genTime
```

`KC_GetTimeFromSig` даёт **только** genTime; без TSP-токена → `0x08F0004A`
(`KCR_NOTSATOKEN`). Остальные поля TSP — своим разбором ASN.1 TimeStampToken.

- **`KC_TSASetUrl` обязателен для тест-среды.** Встроенный дефолтный TSA —
  *продакшн*-респондер; тестовый сертификат он не метит и `SignData` с
  `KC_WITH_TIMESTAMP` возвращает **пустой** результат при `rc==0` (не ошибку).
  Для тест-ключа явно указывай `http://test.pki.gov.kz/tsp/` (со слэшем и без —
  оба работают). Пустой URL в `KC_TSASetUrl` — это «оставить дефолт», а не сброс.

## Хеш-стриминг больших данных

`HashData(algorithm, flags, data, len, out, &outLen)` → `SignHash(alias, flags,
hash, hashLen, out, &outLen)` — подписать предвычисленный дайджест, не таща весь
объём в CMS (плюс `KC_IN_FILE`/`KC_DETACHED_DATA`). `HashData` над фиксированным
вектором + сверка с эталоном — годный **смоук-самотест** библиотеки.

**Проверено на v2.0.13 (эмпирически):**
- **`HashData` выбирает алгоритм ФЛАГОМ, не строкой `algorithm`.** Имена/OID в
  `algorithm` (`SHA256`, `GOST3411-2015-512`, `1.2.398…`) → `0x08F00015`
  (`unknown algorithm`). Работает `flags = KC_HASH_SHA256`/`KC_HASH_GOST95` (→
  ГОСТ34311-95, 32 байта). Отдельного флага **ГОСТ-2015 нет** — standalone-хеш
  ГОСТ-2015 не отдаётся; для ГОСТ-2015-ключей хешируй внутри `SignData`, а не
  через `HashData`+`SignHash`.
