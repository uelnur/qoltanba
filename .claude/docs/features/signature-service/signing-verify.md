# Подпись / проверка: CMS, XML, WSSE, co-sign, контент, TSP

Часть фичи `signature-service` — сначала [`index.md`](index.md).
Поведение sign/verify и что извлекается из подписи (доменный слой). Механика C-API
(функции, флаги, рецепты вызовов) — в
[`../../kalkan-api/signing.md`](../../kalkan-api/signing.md); глубокий разбор
TSP-токена (RFC 3161) и WSSE — через [`ncanode.md`](../../ncanode.md).

## CMS (`SignData` / `VerifyData`)

- **Подпись** (флаги `KC_SIGN_CMS|KC_OUT_PEM`) → PEM-блок `-----BEGIN CMS-----`.
  Успешна для всех профилей.
- **Проверка** вызывается **с теми же флагами, что подпись** + исходные данные и
  подпись. Неверные флаги → `0x08F00039` (`KCR_SIGNFORMMAT`).
- **Успех = rc 0.** `outVerifyInfo` даже при успехе = `error:00000000:...` (нули =
  «нет ошибки») — по тексту не судить.
- **Срок сертификата** сверяется с системными часами → без `KC_NOCHECKCERTTIME`
  подпись падает `0x08F00042` (`KCR_CERTTIMEINVALID`). Нужен явный параметр.
- **Проверка с cert-time якорит цепочку к доверенному корню → CA должны быть загружены.**
  С `CheckCertTime` (без `KC_NOCHECKCERTTIME`) `VerifyData` для CMS валидирует цепочку
  подписанта до trusted-root, и без загруженных CA падает тем же `0x08F00042` даже для
  валидного во времени серта. Поэтому драйвер `VerifyCMS` **загружает `TrustedCerts`**
  (как и `VerifyXML`) перед проверкой. Обратная сторона: **без cert-time (`KC_NOCHECKCERTTIME`)
  цепочка к корню не проверяется** — `Valid=true` вернётся и для самоподписанного серта;
  где нужна привязка к якорю (напр. OIDC-логин), проверка обязана идти с cert-time и
  настроенными анкорами.

## Извлечение подписанта

- **CMS:** `KC_GetCertFromCMS(cms, len, sigId, KC_IN_PEM|KC_OUT_PEM, …)` — `sigId`
  **1-based**; возвращает PEM листа → полный разбор через `X509CertificateGetInfo`
  (см. [`certificates.md`](certificates.md)).
- **XML:** `KC_getCertFromXML(xml, len, sigId, …)` (1-based); `VerifyXML` даёт
  структурированный per-signature `outVerifyInfo` (`Signature N 1\nId = 1\n
  certificateSerialNumber=…\nsignatureAlgorithm=…`); `KC_getSigAlgFromXML` — алгоритм.

## Множественная подпись (co-sign разными людьми)

Проверено: один документ подписывают двое — извлекается полная инфа о каждом.

- **Как:** `SignData` принимает предыдущую подпись в `inSign` → добавляет ещё один
  `signerInfo`. Для XML — повторный `SignXML` (второй `<Signature>`). Ключи
  переключаются повторным `KC_LoadKeyStore`.
- **Извлечение всех:** перебор `sigId` (1-based) через `KC_GetCertFromCMS` /
  `KC_getCertFromXML`. **Реализовано для обоих:** драйвер `VerifyCMS` **и**
  `VerifyXML` заполняют `Signers[]` перебором до пустого ответа (не одного).
- **Ловушка порядка:** `sigId` **≠ порядок подписания** и различается форматами — в
  CMS `#1` = **последний** добавленный, в XML `#1` = **первый**. → В контракте
  `signers[]` с явными полями; смысл к индексу не привязывать (использовать
  `signingTime` / идентичность серта).
- Верификация **мультиподписи** требует загруженных доверенных CA-сертов (иначе
  `0x08F00022` `KCR_LOADTRUSTEDCERTSERR` у XML). Извлечение подписантов от этого не
  зависит.

## Объяснитель «почему невалидно» (diagnosis)

Флаг запроса `explain` наполняет `VerifyOutput.Explanation` (`internal/core/explain.go`):
упорядоченный `Diagnosis` — `valid` + `summary` (одна строка-итог) + `steps[]`, где каждый
шаг `{step, status, summary, action}`. Шаги в фиксированном порядке: `signature`
(математика подписи; при провале `summary`/`action` берутся из каталога ошибок через
`LibError`), `certificateTime` (окно `notBefore..notAfter` против «сейчас» — **fail** если
verify шёл с cert-time, иначе **warn**; отсутствие окна → **unknown**), `chainComplete`,
`trustAnchor` (обе — **warn**, не фейл: криптовалидность ≠ доверие), `chainSignatures`
(**skipped**, пока не включён `trust.verify-chain`), `revocation` (**skipped** — verify не
проверяет отзыв; action указывает на `/cert/validate` и `/verify/at`). Статусы —
`pass/fail/warn/skipped/unknown`; по нескольким подписантам агрегируется worst-wins. Это
**чистая синтез-надстройка** над уже собранным результатом (без новых вызовов Kalkan/сети),
поэтому одинаково доступна на всех транспортах и в batch.

## Восстановление оригинального содержимого

- **Attached-CMS** (по умолчанию, без `KC_DETACHED_DATA`): контент вложен →
  восстанавливается `VerifyData` c `inData=NULL`, флаги `KC_SIGN_CMS|KC_IN_PEM`
  **без** `KC_OUT_PEM` (иначе либа обернёт в PEM и вернёт пусто).
- **Detached-CMS** (`KC_DETACHED_DATA`): контента в подписи нет по определению —
  оригинал подаётся отдельно, восстановить нельзя.
- **XML enveloped:** подписанный документ сам и есть содержимое.
- Признак `detached` — часть ответа контракта.

## Метка времени (TSP)

- `KC_GetTimeFromSig` даёт **только genTime**; без TSP → `0x08F0004A`
  (`KCR_NOTSATOKEN`). Извлечение метки требует подписи с флагом `KC_WITH_TIMESTAMP`
  и доступа к TSA (`test.pki.gov.kz`) — сетевой вызов.
  > **TSP при подписании (реализовано):** флаг запроса `withTimestamp` — **tri-state**
  > (`nil` → дефолт сервиса `sign.default-timestamp`, значение переопределяет).
  > Биндинг Kalkan даёт **только `KC_TSASetUrl`** (URL), **сеттера политики TSA нет** —
  > политику Kalkan выбирает по алгоритму (для GOST-2015 → `TSA_GOST2015_POLICY`);
  > `tsaPolicy` как запросную ручку через C-API не сделать (нужен свой TSP-клиент).
  > При успешной подписи с меткой домен **эхо-ит разобранный TSP в sign-ответе**
  > (CMS: парсит свой же результат через `internal/cms`; XML/WSSE — только
  > `cadesLevel`). Итог: `cadesLevel` = `T`/`BES`, `timestamp` (CMS) без второго
  > вызова verify.
- Остальные поля TSP (serialNumber, policy, tsa, hashAlg, imprint) — **разбором
  ASN.1** TimeStampToken → TSTInfo самим. Токен — unsigned attribute с OID
  `1.2.840.113549.1.9.16.2.14`; imprint считается **от SignatureValue подписанта**,
  а не от контента. Политики TSA и таблица hash-OID → [`nuc-pki-reference.md`](../../nuc-pki-reference.md).
  > **Реализовано:** `internal/cms` (свой `encoding/asn1`) парсит CMS SignedData —
  > per-signerInfo `signingTime` (signed-attr `…1.9.5`), `signatureAlgorithm` и
  > TSP-токен → TSTInfo (serialNumber/policy/genTime/hashAlg/imprint/tsa). В
  > `verify` эти поля матчатся к подписанту **по серийнику** сертификата и кладутся
  > на `signers[]` (`signingTime`, `signatureAlgorithm`, `timestamp`).
  > **`cadesLevel=T` требует двух независимых фактов** (`internal/core/timestamp.go`),
  > и они ломаются по-разному:
  > 1. **imprint привязывает токен к этой подписи.** Токен — обычный unsigned-атрибут,
  >    его можно перенести из чужого контейнера, и разбор ASN.1 этого не заметит.
  >    Пересчитываем дайджест **SignatureValue подписанта** алгоритмом из самого токена
  >    и сравниваем с `messageImprint` → `timestamp.imprintVerified` (tri-state:
  >    `true`/`false`/отсутствует = проверить не смогли) + `imprintNote`.
  > 2. **TSA действительно подписал токен.** Один imprint доказывает лишь, что кто-то
  >    собрал структуру, называющую эту подпись. TimeStampToken — это сам по себе CMS
  >    SignedData, поэтому проверяем его **обычным путём verify** (`VerifyCMS` по
  >    `Timestamp.Raw`), без второй реализации подписи → `timestamp.signatureVerified`
  >    + `signatureNote`. Проверка времени серта там **выключена намеренно**: метка
  >    обязана переживать серт TSA, и отвергать старый токен из-за истёкшего издателя
  >    значит ломать то, ради чего метка ставится.
  >
  > `T` — только когда оба `true`; иначе `BES` + warning. Fallback по
  > `KC_GetTimeFromSig` (только genTime, токен не разобран) `T` не ставит: сверять нечего.
  >
  > **Откуда дайджесты (замерено на боевом TSA, не выведено):** реальный НУЦ-TSA под
  > политикой `1.2.398.3.3.2.6.4` кладёт imprint с OID `1.2.398.3.10.1.3.3` =
  > **ГОСТ Р 34.11-2015 (512)**, 64 байта. Kalkan его **не умеет**: `HashData` в
  > v2.0.13 знает только `KC_HASH_SHA256`/`KC_HASH_GOST95`, на любое написание 2015
  > отвечает `0x08F00015 «unknown algorithm»`. Поэтому Streebog-256/512 считается
  > **в Go** (`github.com/deatil/go-cryptobin`, Apache-2.0 — GPL-реализации этого
  > семейства не годятся). Это **хеш для сравнения, а не проверка подписи**: крипто-
  > вердикты по-прежнему за библиотекой, граница из `architecture.md` не сдвинута.
  > SHA-1/256/384/512 — стандартной библиотекой Go; старый ГОСТ 34.311-95 — через
  > `Provider.Hash`. Неизвестный OID дайджеста **не угадываем**: посчитать не тем
  > алгоритмом значит объявить исправную метку подделкой.
- **Структура токена:** TimeStampToken = CMS SignedData c `eContentType = id-ct-TSTInfo`;
  внутри `TSTInfo ::= SEQUENCE { version, policy OID, messageImprint {algId,
  hashedMessage}, serialNumber INTEGER, genTime GeneralizedTime(UTC), tsa [опц.]
  GeneralName }`. `serialNumber`/`hash` отдаём как HEX (нижний регистр). Серт TSA
  ищется по `SID` внутри собственного CMS-мешка токена.
- **Если запрашиваем метку сами:** POST на TSA `Content-Type:
  application/timestamp-query`, в запросе `certReq=true` и nonce; ответ обязательно
  **валидировать против запроса** (nonce/imprint/policy), а токен — против серта TSA
  (подпись + imprint).

## XML / WSSE / ZIP

- **XML** round-trip проверен (`SignXML`/`VerifyXML`, узлы можно пустые, вывод —
  enveloped). Transforms: enveloped + C14N **с** комментариями
  (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`); KeyInfo —
  X509Certificate; алгоритм-URI по OID подписи ([`nuc-pki-reference.md`](../../nuc-pki-reference.md)).
  Нюансы: DOM **namespace-aware**, префикс `ds:` обязателен (verify ищет
  `ds:Signature`); UTF-8 `.trim()` перед разбором; `Reference URI=""` = весь документ,
  иначе `#id` (id-атрибут должен быть зарегистрирован как XML ID); подрезку
  whitespace-узлов делать **до** подписи (меняет каноничную форму).
- **XML мультиподпись — проверять/снимать LIFO:** внешняя (последняя добавленная)
  подпись накрывает вложенные → сначала верифицировать и отсоединить её.
- **WSSE — только один подписант.** exclusive-c14n **без** комментариев
  (`http://www.w3.org/2001/10/xml-exc-c14n#`); серт как `KeyIdentifier` (base64 X509,
  ValueType v3) внутри `SecurityTokenReference`; Body по `wsu:Id="id-<uuid>"`,
  `mustUnderstand=1`. NS: WSU `…oasis-200401-wss-wssecurity-utility-1.0.xsd`, secext
  `…-wssecurity-secext-1.0.xsd`.
- **ZIP** — `ZipConSign`/`ZipConVerify` + `KC_getCertFromZipFile` (файловый I/O).

## Пресеты политик подписи (ETSI-уровни)

`core.SignaturePolicy` (`internal/core/policy.go`), поле запроса `policy`:
`cades-b` / `cades-t` / `xades-b` / `xades-t`. Пресет разрешает **формат** и
**дефолт метки времени**, чтобы вызывающий заявлял нужный уровень
интероперабельности, а не собирал флаги вручную.

- Явный `format`, противоречащий пресету, — **ошибка**, а не тихое
  переопределение: заявлены два разных намерения, выбрать может только вызывающий.
- Явный `withTimestamp` **побеждает** дефолт уровня (результирующий `cadesLevel`
  это отразит) — уровень задаёт умолчание, а не клетку.
- **LT/LTA не заявлены намеренно:** им нужен вложенный revocation-материал (LTV),
  которого пока нет; назвать уровень раньше реализации значит пообещать
  интероперабельность, которой сервис не даёт.
- **Профиля `egov` нет:** его требования — доменное правило РК, не зафиксированное
  в доках; выдумывать набор флагов под именем госстандарта нельзя. Нужен —
  подтвердить состав у владельца.

## Долгосрочная валидация (CAdES-LT)

`core.Archive` (REST `POST /sign/archive`, dispatch-op `archive`) + `internal/cms`
(`AddLTV`, `EmbeddedEvidence`).

Подпись проверяется сегодня потому, что отвечает OCSP-респондер. Через пять лет
респондера может не быть, серт давно истечёт, а подпись — математически по-прежнему
верная — окажется непроверяемой. Архивирование собирает доказательства, пока они
добываемы, и кладёт их внутрь контейнера.

- **Куда кладём:** unsigned-атрибуты `revocation-values` (1.2.840.113549.1.9.16.2.24)
  и `certificate-values` (…2.23). Они **вне подписи** — поэтому дописывать их в уже
  подписанный контейнер законно.
- **Как пересобираем:** тело SignedData и SignerInfo склеиваются из **собственных
  исходных байтов**, меняется только дополняемый элемент. Перекодировать
  разобранные поля через `asn1.Marshal` нельзя: их DER может измениться, а подпись
  покрывает часть из них. (Грабли, на которые наступили: `asn1.RawValue`
  игнорирует теги полей структуры, поэтому `explicit,tag:1` над RawValue молча даёт
  нетегированный элемент — обёртки строятся вручную.)
- **Идемпотентность:** повторный проход не дублирует атрибут и не затирает чужие
  вложенные данные.
- **Частичный успех:** недоступный OCSP не отменяет архивацию (цепочку вложить
  всё равно стоит), но пишется предупреждение — молчать о ненайденном
  доказательстве нельзя.
- **LTA не делаем:** archive-timestamp — это свежий запрос к TSA поверх готовой
  структуры плюс собственное расписание перештамповки, отдельная операция.
