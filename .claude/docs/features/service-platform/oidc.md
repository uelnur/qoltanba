# OIDC-провайдер «вход по ЭЦП»

Часть сервисной платформы — сначала [`index.md`](index.md). Прикладной turnkey-flow
поверх крипто-примитивов: превращает detached-CMS-подпись пользователя над серверным
nonce в стандартные OpenID Connect токены. Крипто-домен (verify/validate/claims) — в
[`../signature-service/index.md`](../signature-service/index.md); направление и границы
объёма — [`../../roadmap.md`](../../roadmap.md).

> **Объём — API-flow + discovery, не полный auth-code.** Мы отдаём backend-строительные
> блоки (challenge/verify/token + discovery/JWKS/userinfo); браузерную часть
> (NCALayer/eGov-QR) ведёт приложение-потребитель. Hosted login-страница и JS-виджет —
> **вне текущего объёма** (не-цель UI/фронтенд-подпись, [`../../architecture.md`](../../architecture.md)).

## Слои

`internal/oidc` — **application-сервис**, аналог `internal/jobs`: не домен и не транспорт,
а оркестрация над `core.Service` (через узкий порт `Verifier`: `Verify`+`Validate`) плюс
не-крипто-концерн — выпуск собственных JWT. REST-адаптер
(`internal/transport/rest/oidc.go`, опция `rest.WithOIDC`) — тонкий. Включается по конфигу
(`oidc.enabled`), собирается в `buildOIDC` (main), served **только по REST**.

## Две подписи — не путать

- **ЭЦП пользователя** — GOST, проверяется Kalkan'ом через домен. Пользователь подписывает
  nonce как **detached CMS**; ключ остаётся у NCALayer/eGov.
- **Токен сервиса** — `id_token`/`access_token` подписаны **RS256** локальным ключом
  сервиса и публикуются через `jwks_uri`, чтобы **любой стандартный OIDC-клиент** их
  проверил (GOST-подпись стоковый RP проверить не смог бы). Минимальный JWS на stdlib
  (без JOSE-зависимости), как ASN.1 в `internal/cms`.

## Flow (durable-семантика)

1. **`POST /oidc/challenge`** → сервер генерит 32-байтный nonce (crypto/rand), сохраняет
   single-use challenge с TTL, отдаёт `{challengeId, data (base64 nonce), alg:"CMS-detached",
   expiresIn}`. Опциональные `nonce`/`state` от RP эхо-ятся (RP-nonce попадёт в id_token).
2. Клиент подписывает **raw-байты nonce** (декодированные из `data`) как detached CMS
   через NCALayer/eGov.
3. **`POST /oidc/verify`** `{challengeId, signature, clientId?}` →
   - `Consume(challengeId)` — **атомарно** get+mark-used (анти-replay); повтор → `used`.
   - Проверка TTL (истёк → отказ).
   - Домен `Verify{Format:CMS, Data:nonce, Detached:true, CheckCertTime:true,
     ExtractClaims:true}`; требуется `Valid` и ≥1 signer с непустым `sub`.
     **`CheckCertTime:true` — граница авторизации, не только срок:** для CMS он
     форсирует Kalkan проверить цепочку подписанта **до доверенного корня НУЦ** (без
     него `verify` вернул бы `Valid=true` для любого самоподписанного серта → обход
     логина). Отсюда **обязательность trust-анкоров** (ниже).
   - Если `oidc.require-ocsp` (дефолт on) — домен `Validate{Method:OCSP}`; `revoked` → отказ.
   - Минт `id_token` (iss/sub/aud/iat/exp/auth_time + RP-nonce + RK-claims из
     `ClaimsFromCertificate`) и `access_token` (те же claims + `token_use:access`), оба
     RS256. Ответ — `{id_token, access_token, token_type:"Bearer", expires_in}`.
4. **`GET /oidc/userinfo`** (`Authorization: Bearer <access_token>`) → claims (валидация
   подписи+exp; токены **stateless**, сессионного стора нет — только challenge-store).

## Discovery / JWKS

- **`GET /.well-known/openid-configuration`** — issuer, `jwks_uri`, `token_endpoint`
  (=`/oidc/verify`), `userinfo_endpoint`, кастомный `challenge_endpoint`,
  `id_token_signing_alg_values_supported:[RS256]`, `subject_types_supported:[public]`,
  `scopes_supported`, `claims_supported`, `grant_types_supported:[urn:qoltanba:…:ecp]`.
  `authorization_endpoint` **не заявляем** (нет browser-redirect — осознанный объём).
- **`GET /oidc/jwks.json`** — публичный RSA-ключ (JWK: kty/use/alg/kid/n/e). `kid` =
  base64url(SHA-256(DER SubjectPublicKeyInfo)).

## Ключ подписи токенов

`oidc.key-path`: пусто → **ephemeral** in-memory RSA-2048 (kid ротируется на рестарте,
живые токены инвалидируются — лог-warn); задан → **load-or-generate+persist** (0600),
стабильный kid. Помечен `secret:true` в конфиге.

## Ошибки (OAuth2-конверт)

REST отдаёт `{error, error_description}` (не общий error-конверт сервиса — RP ждут
OAuth2-форму). Маппинг: `challenge not found/expired/used` → `invalid_grant` (400);
`signature rejected`/`certificate revoked` → `access_denied` (401);
`token invalid/expired` → `invalid_token` (401); прочее → `server_error` (500).

## Trust-анкоры — обязательны

OIDC **требует** настроенных якорей CA НУЦ (`trust.use-rk-registry` или `trust.ca-dir`):
`CheckCertTime:true` при verify валидирует цепочку подписанта до доверенного корня, и это
**граница авторизации** — без анкоров проверка падает для любого серта (`0x08F00042`, тот
же код, что «нет CA-цепочки»), а если её отключить — залогинится кто угодно. `buildOIDC`
предупреждает при включённом OIDC без анкоров. (RequireOCSP тоже опирается на анкоры.)

## Границы и заметки

- **verify-only-совместимо:** OIDC лишь проверяет подпись пользователя и читает серт —
  Kalkan-ключ сервиса не нужен; RS256-ключ токена независим. Гейта нет. **Но** trust-
  анкоры нужны и здесь (см. выше).
- **Challenge-store** — `memory` (дефолт, ephemeral) или `bolt` (durable/мульти-инстанс,
  0600), образец `internal/jobs`. Фоновый reaper чистит истёкшие по `oidc.challenge-ttl`.
- **Метрика** `qoltanba_oidc_challenges` (gauge активных challenge).
- **На будущее:** authorization_endpoint + hosted-login (plug-and-play Socialite),
  ротация JWKS/несколько kid, refresh-токены — см. [`../../roadmap.md`](../../roadmap.md).

## Браузерный поток (authorization code + PKCE)

Ставка «стоковый OIDC-клиент без кастомного драйвера» закрыта: `GET /oidc/authorize`
(страница входа) → подпись → `POST /oidc/authorize` → редирект с `code` →
`POST /oidc/token` меняет код на токены. API-grant (`/oidc/challenge` +
`/oidc/verify`) остался как есть — для потребителей, которые ведут handshake сами;
в discovery он теперь объявлен отдельно (`challenge_endpoint`/`verify_endpoint`),
а `token_endpoint` указывает на стандартный `/oidc/token`.

**Что защищает поток:**

- **Реестр клиентов** (`oidc.clients`, формат `client_id|secret|redirect_uri[|…]`):
  редирект возможен только на **точно зарегистрированный** URI — префиксное
  сравнение это и есть open redirect. Пустой secret = публичный клиент.
- **Порядок проверок:** сначала клиент и redirect_uri, потом всё остальное. Любая
  более поздняя ошибка сообщается *на* этот URI, и отправить её на непроверенный
  адрес — сама по себе уязвимость.
- **PKCE (только S256) обязателен для публичных клиентов**; `plain` отклоняется —
  он не даёт защиты по сравнению с её отсутствием.
- **Код одноразовый и короткоживущий** (60 с, изымается атомарно), привязан к
  клиенту, redirect_uri и PKCE-челленджу; всё это перепроверяется при обмене.
  Secret confidential-клиента сверяется constant-time.
- Коды — in-memory и node-local намеренно: живут секунды и потребляются тем же
  браузерным переходом, переживать рестарт им незачем.

**Страница входа** — единственный UI, который сервис хостит, и это осознанно
тонкий glue (грань не-цели «не делаем UI» зафиксирована в roadmap): она просит
подпись у NCALayer по его локальному WebSocket (`wss://127.0.0.1:13579`) и
отправляет результат обратно. Ключ остаётся у пользователя — сервис видит только
подпись. Второй способ — **eGov Mobile**: кнопка создаёт sign-сессию через существующие
`/qr/*` (собственного серверного кода у страницы нет), рисует QR и поллит до
вердикта; при выключенном QR-оркестраторе вариант не отображается и его скрипт в
страницу не попадает. Третий — ручная вставка CMS, чтобы страница работала там, где
нет ни NCALayer, ни eGov Mobile. Страница самодостаточна и не кэшируется (`no-store`) —
она несёт одноразовый челлендж.
