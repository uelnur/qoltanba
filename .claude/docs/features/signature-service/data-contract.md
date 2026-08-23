# Контракт запрос/ответ (черновик)

Часть фичи `signature-service` — сначала [`index.md`](index.md).

> **Состав полей не финальный.** Точная форма JSON/proto ещё уточняется вместе с
> раскладкой проекта. Здесь — только **durable-семантика** извлечения, которая
> переживёт смену имён полей. Живой черновик формы — `qoltanba/api/qoltanba-draft.proto`
> (gRPC + JSON-зеркало для REST/socket/CLI/MQ). На конкретные имена полей не
> завязываться, пока контракт не зафиксирован владельцем проекта.

## Что останется верным независимо от формы

- **Кодировки:** бинарные поля — base64; сертификаты — PEM/DER; время — RFC3339
  (исходный `DD.MM.YYYY HH:MM:SS ±HH:MM` нормализуется).
- **Секреты** (`password`, `pin`, inline `p12`) — **только во входе**, никогда в
  ответах/логах/метриках/трейсах.
- **Best-effort извлечение:** недоступное поле → `null` + запись в `warnings`
  (`{field, reason}` с кодом `KCR_*`), а не отказ всей операции.
- **Ошибка криптоядра** отделена от бизнес-результата: `libError` или `null`;
  статус операции — из rc, не из текста (см. [`signing-verify.md`](signing-verify.md)).
  `libError` несёт сырьё для диагностики (`code` = `KCR_*`, `text` = текст либы) **и**
  дружелюбный рендер из **каталога ошибок**: `key` (стабильный локаль-независимый id,
  напр. `cert.expired`), `message`, `action`. Каталог — единый источник правды в
  `internal/provider` (`Explain`, keyed по sentinel-ам); `message`/`action` сейчас на
  английском, `key` — шов под будущую локализацию. Тот же рендер идёт в конверт
  **жёсткой** ошибки транспорта (REST `error.{code,message,action}`, CLI, gRPC-status).
- **`signers[]`** — массив с явными полями; **индекс не несёт смысла** (≠ порядок
  подписания, различается CMS/XML). Признаки `detached`, `chainComplete`,
  `trustAnchorFound`, `chainSignaturesVerified` (крипто-валидна ли цепочка —
  проверяет Kalkan, вкл. ГОСТ; только при включённой проверке), `cadesLevel` —
  часть ответа. Per-signer (CMS, из SignedData): `signingTime`,
  `signatureAlgorithm`, полный `timestamp` (TSTInfo: serialNumber/policy/genTime/
  hashAlgorithm/hash/tsa).
- **`revocation`** несёт `revoked`/`reason`/`revocationTime` **и** `thisUpdate`/
  `nextUpdate`/`producedAt` (OCSP) — структурный разбор поверх вердикта Kalkan.
- **Большие данные** передаются по ссылке (`filePath`/`url`), а не inline base64
  (async-задания, потоковая обработка).

## Операции (v1)

`sign.{xml,cms,wsse,zip,hash}`, `verify.{xml,cms,zip}`, `cert.info`,
`cert.validate` — единый контракт на все транспорты, единичный вызов = пакет из
одного элемента. Что делает каждая и какими методами Kalkan — см.
[`signing-verify.md`](signing-verify.md), [`certificates.md`](certificates.md),
[`validation.md`](validation.md). Транспорты, batch и async-задания —
[`../service-platform/index.md`](../service-platform/index.md).
