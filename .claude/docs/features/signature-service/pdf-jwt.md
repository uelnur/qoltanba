# PDF, JWT, Office-документы — форматы вне Kalkan-C-API

Часть фичи `signature-service` — сначала [`index.md`](index.md).
Форматы, которых **нет в криптоядре Kalkan**: их структуру делает отдельный
Go-слой, а саму крипту (hash+sign) — всё равно Kalkan (см.
[`signing-verify.md`](signing-verify.md), [`../../kalkan-api/signing.md`](../../kalkan-api/signing.md)).
Все — **будущие** (nascent), durable здесь — подход и подводные камни, не код.

## PDF (PAdES / CAdES-detached)

- **Подпись — инкрементальное обновление** PDF: добавляется signature-dictionary
  `Filter=ADOBE.PPKLITE`, `SubFilter=ETSI.CAdES.detached` (PAdES-BES), плейсхолдер
  `/Contents`, затем PDF-слой считает `/ByteRange`; метаданные `name=SubjectDN`,
  опц. `location`/`reason`/`contactInfo`/`signDate`.
- **Сама подпись — detached-CMS** над байтами ByteRange (`encapsulate=false`);
  digest-OID по той же таблице sign→digest ([`../../nuc-pki-reference.md`](../../nuc-pki-reference.md)),
  TSP опционально (дефолт `TSA_GOST2015_POLICY` = `1.2.398.3.3.2.6.4`). **Крипта —
  целиком в нашем CMS-слое поверх Kalkan; PDF-либа только структура.**
- **Verify:** перебрать signature-dictionaries (нет подписей — отдельный исход
  «не найдено»); `getContents` = сырой CMS, signed-content = байты по `/ByteRange`;
  пересобрать CMS из (signedContent, contents), проверить каждого подписанта → далее
  OCSP/CRL-валидация ([`validation.md`](validation.md)). `signatureAlgorithm` в ответе
  = строка SubFilter, `digestAlgorithm` = CMS digest-OID.
- **Лицензионный нюанс (design-решение):** PDF-либа берёт на себя только структуру
  (ByteRange + инкрементальная запись) — это переносимая часть; GOST-крипта остаётся
  в нативном слое. Кандидаты — `github.com/digitorus/pdfsign` (MIT, ближайший аналог:
  ByteRange + CMS-плейсхолдер) или `github.com/pdfcpu/pdfcpu` (Apache-2.0).
  **Избегать iText (AGPL) / OpenPDF (LGPL)** — держим разрешительную лицензию.
  Это единственный реально трудозатратный пункт паритета (см. [`../../ncanode.md`](../../ncanode.md)).

## Office-документы (docx / xlsx)

`.docx`/`.xlsx` — это **OPC-пакет (ZIP из XML-частей)**. «Подписать офисный файл»
распадается на две принципиально разные задачи с разницей в трудозатратах на
порядки — не смешивать:

- **A. Подпись над байтами файла (CMS/detached) — тривиально, уже есть.** Файл
  трактуется как непрозрачный блоб: `SignData` (+`KC_IN_FILE`) → detached `.p7s`
  рядом или attached-CMS; проверка симметрична `VerifyData`. Это общий sign-путь,
  отдельной логики не нужно. **Именно так в РК обычно и подписывают офисные файлы.**
  Минус: Word/Excel не покажут «подписано» — подпись живёт снаружи файла.
- **Контейнер «один файл = документ + подпись» — умеренная сложность.** Если нужен
  самодостаточный артефакт: **ASiC-E** (ETSI, ZIP: документ + `META-INF/signatures`
  с CAdES/CMS) — открытый стандарт, проверяемый чужими инструментами; Kalkan даёт
  CMS, мы собираем ZIP-раскладку. Kalkan-native `ZipConSign` — тоже вариант, но
  формат **проприетарный** (не ASiC), проверяется только `ZipConVerify`.
- **B. Встроенная OOXML-подпись, которую видит Office — тяжело И бессмысленно.** Два
  независимых стоп-фактора:
  1. **Примитива в Kalkan нет.** `SignXML` делает свой XMLDSIG-конверт, а не
     OOXML-специфику (`RelationshipTransform`, `Manifest` по частям пакета,
     `SignatureProperties/SignatureTime`, раскладку `<Object>`). Пришлось бы вручную
     собирать OPC-пакет + `SignedInfo` и подписывать его дайджест через `SignHash` —
     а для **ГОСТ-2015 ключей** `HashData`/`SignHash` отдельного хеша не даёт (см.
     [`../../kalkan-api/signing.md`](../../kalkan-api/signing.md)), т.е. схема ломается
     именно на казахстанских ключах. Недели работы + болезненный интероп под Office.
  2. **Office всё равно отвергнет.** Microsoft Office **не знает ГОСТ-алгоритмы** РК и
     **не доверяет корню НУЦ** → покажет «неизвестный алгоритм / недоверенный серт», а
     не «валидно». → **Не-цель проекта** ([`../../architecture.md`](../../architecture.md)).

### Плагин к Word (Office Custom Signature Provider) — почему тоже нет

У Office есть официальная точка расширения — **Custom Signature Provider** (COM-объект
`SignatureProvider`, только COM-add-in, не VBA; умеет своё хеширование/подпись/
проверку). Прецедент — **КриптоПро Office Signature** (ГОСТ РФ в Word/Excel 2007–2021).
Обернуть Kalkan так технически можно, **но не в этом проекте**:

- **Ставится на КАЖДОЙ машине** — подписанта *и* всех проверяющих; без плагина у
  получателя подпись = «невозможно проверить». Это убивает саму цель встроенной
  подписи (zero-install проверка) и повторяет дистрибуционную боль NCALayer.
- **Только Windows + десктопный Office** (ни macOS, ни Web, ни мобильный) — MS двигает
  всё в веб, где механизма нет.
- **Отдельный C++/COM Windows-продукт**, не переиспользует наш Go-код/транспорты —
  вне рамок тонкого серверного FFI-сервиса.

Прагматичная альтернатива «документ валиден» без плагина на десктопах — **серверная
проверка** (`verify` + портал/QR-верификация), работающая с любого устройства.

## JWT (GOST)

- Стандартный compact `base64url(header).base64url(payload).base64url(signature)`;
  header — только `alg` + `typ`. Подпись: `header.payload` → hash → GOST-sign →
  base64url.
- **`alg`:** `GG2015` / `GG2004` (GOST, через нативный слой) плюс ES256/384/512,
  RS256/384/512 (RSA/ECDSA — можно стоковой Go-JWT-либой).
- **`x5c` НЕ используется** — сертификат в токен не встраивается; при decode/verify
  приходит отдельным полем `key` (base64 X509). **Невалидная подпись при decode — не
  ошибка:** отдавать `200 { valid: false }`. Claims произвольны (exp/iss не форсим).
