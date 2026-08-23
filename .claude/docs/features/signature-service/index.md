# Сервис ЭЦП поверх Kalkan — обзор

**Scope.** Доменные факты сервиса подписи/проверки ЭЦП РК поверх нативной
библиотеки Kalkan: интеграция с библиотекой, извлечение данных сертификата,
sign/verify (CMS/XML/WSSE/ZIP), валидация (OCSP/CRL) и построение цепочки.
Таблицы OID/алгоритмов/ролей — вне этого дока → [`nuc-pki-reference.md`](../../nuc-pki-reference.md).
Паритет/сравнение с чужой реализацией → [`ncanode.md`](../../ncanode.md).

> **Слои зафиксированы, наполнение — нет.** Целевая раскладка (драйвер/домен/
> транспорт, ports & adapters) описана в [`architecture.md`](../../architecture.md);
> конкретные файлы внутри пакетов ещё пишутся. Этот док фиксирует то, что переживёт
> реализацию: поведение библиотеки, форматы, производные поля, семантику операций.
> Ссылки на конкретные файлы app-кода помечены *(nascent)*.

## Взгляд с высоты

Запрос проходит транспортно-независимое ядро к единственному месту с FFI и
дальше — в нативную библиотеку:

```
транспорт → core (Go-структуры) → Provider (FFI, пул воркеров) → libkalkancryptwr-64.so
                                        │                              (+ libkalkancrypto.so, OpenSSL-1.1-форк)
                                        └─ KeySource / trust-store (CA-реестр РК)
```

Почему так: криптографию **не пишем сами** — всё делает Kalkan; наш код — это FFI +
удобный API + исчерпывающее (best-effort, по-полевое) извлечение всего, что
библиотека способна отдать. Нативная либа не тред-безопасна → сериализация через
пул воркеров, прибитых к OS-потокам. Библиотеку **не храним в репозитории** — её
предоставляет потребитель (Bring-Your-Own-Library), поэтому при старте идёт
проверка совместимости и карта возможностей.

Базовые операции: `sign.{xml,cms,wsse,zip,hash}`, `verify.{xml,cms,zip}`,
`cert.info`, `cert.validate` — каждая доступна из всех транспортов, в единичном и
пакетном варианте, синхронно и как async-задание для больших файлов.

## Gotchas (проверено эмпирически, не выводится из кода)

- **Отсутствие поля сертификата — норма, не ошибка.** `X509CertificateGetInfo` на
  недоступное поле возвращает `0x08F00038` (`KCR_GETCERTPROPERR`) → в ответе `null`,
  а не провал операции. Извлечение — best-effort по-полевое.
- **Значения приходят как `имя=значение`** (`C=KZ`, `serialNumber=IIN…`), NUL-терми­
  нированные в дополненных буферах → префикс `имя=` срезать, резать по первому `\x00`.
- **Успех verify = код возврата 0**, а не текст. `outVerifyInfo` даже при успехе
  содержит OpenSSL-строку `error:00000000:...` (нули = «нет ошибки»).
- **sign и verify используют ОДИНАКОВЫЙ набор флагов.** Иначе verify → `0x08F00039`
  (`KCR_SIGNFORMMAT`).
- **Срок сертификата сверяется с системными часами** — без `KC_NOCHECKCERTTIME`
  подпись падает с `0x08F00042` (`KCR_CERTTIMEINVALID`). Нужен явный параметр.
- **Цепочка НЕ вложена в подпись** — в CMS лежит только лист; НУЦ/КУЦ достраиваются
  из CA-источника или по AIA. Индексы подписей (`sigId`) **1-based**.
- **Индекс подписи ≠ порядок подписания** и различается CMS/XML (в CMS первым идёт
  последний добавленный). Смысл к индексу не привязывать.
- **Библиотека не загрузится на системном OpenSSL 3** — ей нужен OpenSSL-1.1-форк
  `libkalkancrypto.so` из комплекта (символы `SRP_*`). Плюс GNU libiconv, pcsclite.
  Детали среды → [`native-library.md`](native-library.md).

## Куда идти дальше

| Под-область | Файл | Триггеры |
|-------------|------|----------|
| **Механика самой библиотеки Kalkan** (C-API): загрузка, функции, флаги, коды, рецепты | [`../../kalkan-api/`](../../kalkan-api/index.md) | KalkanCrypt.h, KC_*, KCR_*, dlopen, флаги, сигнатуры, рецепты вызовов |
| BYOL, карта возможностей, самотест, readiness, параллелизм (сервисные аспекты) | [`native-library.md`](native-library.md) | BYOL, capability, selftest, readiness, пул воркеров |
| Разбор сертификата: форматы полей, профили, производные поля | [`certificates.md`](certificates.md) | X509CertificateGetInfo, iin, bin, ownerType, роли, даты, ФЛ/ЮЛ/ИС |
| Подпись/проверка CMS/XML/WSSE, co-sign, восстановление контента, TSP | [`signing-verify.md`](signing-verify.md) | SignData, VerifyData, SignXML, мультиподпись, detached, extract, метка времени |
| Валидация, построение цепочки, trust-store, свой слой ревокации | [`validation.md`](validation.md) | OCSP, CRL, X509ValidateCertificate, AIA, цепочка, CA-реестр, revoked, delta-CRL, кэш, refresh, soft-fail, lifecycle |
| PDF, JWT, Office-документы (форматы **вне** Kalkan-C-API, nascent) | [`pdf-jwt.md`](pdf-jwt.md) | PDF, PAdES, ByteRange, pdfsign, JWT, GG2015, base64url, x5c, docx, xlsx, OOXML, OPC, ASiC, ZipConSign, Word-плагин, signature provider |
| OID/роли/алгоритмы (справочник) | [`nuc-pki-reference.md`](../../nuc-pki-reference.md) | OID, EKU-роль, TSA-политика, digest, DN, gender |
| Контракт запрос/ответ (**черновик**) | [`data-contract.md`](data-contract.md) | JSON, proto, операции, warnings, libError, batch, async |
| Рантайм-обвязка: транспорты, batch/async, ключи, observability | [`../service-platform/index.md`](../service-platform/index.md) | REST, gRPC, MQ, job, KeySource, метрики, секреты |

## Карта файлов

**Источники истины (доки):**

- [`../../kalkan-api/`](../../kalkan-api/index.md) — самодостаточный справочник по
  C-API Kalkan (функции, флаги, коды, рецепты, код-примеры). Сюда вынесены все
  эмпирические факты о библиотеке — за ними не надо ходить в код.
- `qoltanba/internal/pki/` — снимки реестров РК (`oids-nuc.json`,
  `ca-registry.json`) + материализация (`oids.go`, `ca.go`). Значения — из
  официальных реестров, см. [`nuc-pki-reference.md`](../../nuc-pki-reference.md).
- Рантайм-дизайн (транспорты, источники ключей, observability, безопасность,
  batch/async) — [`../service-platform/index.md`](../service-platform/index.md);
  слои и границы — [`architecture.md`](../../architecture.md).

**App-код (nascent):** слои — драйвер `internal/native` (cgo/Provider), домен `core`,
транспорты `transport/*`, инфраструктура (`internal/pki` и др.). Границы и правила —
[`architecture.md`](../../architecture.md); файлы внутри ещё наполняются.

## Связанные доки

- [`architecture.md`](../../architecture.md) — слои, правило зависимостей, конвенции.
- [`../service-platform/index.md`](../service-platform/index.md) — транспорты, ключи, observability.
- [`ncanode.md`](../../ncanode.md) — паритет полей и что отдаём сверх.
- [`nuc-pki-reference.md`](../../nuc-pki-reference.md) — OID/алгоритмы/DN/роли.
