# QR-подписание/авторизация через eGov Mobile (оркестратор)

Часть платформы — сначала [`index.md`](index.md). Turnkey-инструмент, чтобы
бэкендер встроил **подписание и вход по ЭЦП через eGov Mobile** без крипто-кода и
**без нашего фронтенда**: сервис отдаёт QR как base64 PNG (потребитель рендерит
сам), хостит одноразовую TTL-сессию, принимает подпись, проверяет её и отдаёт
результат/токен. Пакет `internal/qr`; REST-адаптер `internal/transport/rest/qr.go`.

Это **не крипто и не sign-эндпоинт**, а доменно-тонкий оркестратор: сама подпись
client-side (ключ не покидает телефон), сервис лишь оркеструет сессию и делает
серверную верификацию — тот же CMS/XML, что и `POST /verify`. Зеркалирует
`internal/oidc` (сессия/consume/nonce/store) и `internal/jobs` (webhook, client-safe
`View`).

## Внешний протокол (факт)

eGov QR — «шлюз» с тремя вызовами: **register** (`POST /api/egovQr` →
`{qrCode, eGovMobileLaunchLink, eGovBusinessLaunchLink, dataURL, signURL,
expireAt}`) → приложение качает данные по `dataURL` и кладёт подпись по `signURL`,
которые **информационная система формирует как одноразовые публичные** → **poll**
подписей. `signMethod ∈ CMS_WITH_DATA | CMS_SIGN_ONLY | XML | SIGN_BYTES_ARRAY |
MIX_SIGN`. Точная строка `qrCode`/формат launch-link задокументированы на **Smart
Bridge** за регистрацией сервиса; SIGEX — сторонний шлюз, реализующий тот же
контракт (доказательство, что шлюз может быть не официальный).

## Три профиля (конфиг `qr.default-profile`, override полем `profile` запроса)

- **`agnostic`** (self-hosted, дефолт) — дженерик: QR несёт наш публичный
  `dataURL`, обобщённый клиент/интеграция потребителя качает данные и постит
  подпись. Без eGov-специфики.
- **`egov`** (self-hosted) — мы сам шлюз: `AppData` отдаёт `documentsToSign`,
  `qrCode`/launch-link — по конфиг-шаблону (`{dataUrl}`/`{signUrl}`/`{id}`). Живой
  скан eGov Mobile требует регистрации потребителя на Smart Bridge — автотестами
  проверяется только структурно.
- **`relay`** (клиент шлюза) — мы клиент готового шлюза (SIGEX): `Prepare` делает
  register+upload, `Poll` тянет подпись по upstream `signURL`. Работает **сегодня
  без Smart Bridge**. Требует `qr.relay-url` (напр. `https://sigex.kz`).

## Режим результата (`qr.default-mode`, override полем `mode`)

- **`sign`** — сессия возвращает `SignResult{signature, valid, signers, claims}`.
- **`auth`** — «вход по ЭЦП через QR»: подписывается серверный nonce, из claims
  выпускаются **OIDC-токены** через общий `oidc.Provider.IssueTokens` (единый
  Signer/JWKS/issuer с OIDC-flow). Требует `oidc.enabled=true`.

## Поток и эндпоинты

REST-only (как OIDC). Consumer-facing на work-порту, app-facing — публичные (их
дёргает eGov Mobile через nginx потребителя):

1. `POST /qr/sessions` `{mode?, profile?, signMethod?, data|documents, clientId?,
   nonce?, callbackUrl?, ttlSeconds?}` → `{sessionId, qr (base64 PNG), payload,
   eGovMobileLink, eGovBusinessLink, dataUrl, signUrl, expiresIn}`.
2. Потребитель рендерит QR у себя; поллит `GET /qr/sessions/{id}` (200 + `View`:
   `status` + `result`) **или** получает наш webhook на `callbackUrl` при
   терминальном статусе.
3. eGov Mobile сканирует QR → `GET /qr/a/{id}` (данные-на-подпись) → подписывает →
   `POST /qr/a/{id}` (подпись). Для `relay` шаги 3 идут в upstream-шлюз, а наш
   оркестратор ленитво поллит его при `GET /qr/sessions/{id}`.
4. На приёме подписи — `verify`+`extract` (+ токены для `auth`), статус
   `verified|failed`, webhook.

Безопасность app-facing: неугадываемый `id` (128-бит) — capability-URL; сессия
**single-use** (anti-replay через `store.Consume`), TTL + фоновый reaper.

## За обратным прокси (важно)

App-facing URL в QR должны быть **внешними**. `qr.public-base-url` (напр.
`https://sign.consumer.kz/esign`) — авторитетен; пусто → выводим из
`X-Forwarded-Proto/Host/Prefix`, иначе `r.Host` (хелпер `publicBaseURL` в
`rest/qr.go`).

## Хранилище, метрики, конфиг

- Store: `memory` (дефолт) | `bolt` (`qr.store`/`qr.bolt-path`) — как OIDC/jobs.
- Метрика: gauge `qoltanba_qr_sessions` (`metrics.BindQR`); request-метрики
  `{transport,op}` — бесплатно из `InstrumentHTTP`.
- Ключи: `qr.enabled`, `qr.public-base-url`, `qr.default-profile`,
  `qr.default-mode`, `qr.session-ttl`, `qr.store`/`qr.bolt-path`, `qr.require-ocsp`,
  `qr.relay-url`/`qr.relay-id`, `qr.organization`. Валидация — `config.Validate`
  (relay-url при relay; auth требует oidc; store-enum; TTL-парс).

## Границы (durable)

Свой relay **не поднимаем** (чужой сервис, против BYOL) — `relay` лишь клиент.
NCALayer/eGov Mobile не проксируем и не заменяем. Точный `qrCode`/launch-link
egov-профиля — за Smart Bridge; шаблоны конфигурируемы. Контракт формы (DTO) —
источник истины, OpenAPI/Postman генерятся (`make openapi`, тег `qr`).
