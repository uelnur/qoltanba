# Dev-песочница — фазовый план и статус

Живой трекер работ. Обновляй статус-галочки **каждую сессию**. Durable-контекст
(архитектура, gotchas, решения) — в [`index.md`](index.md); сюда — фазы, шаги,
находки и «где остановились».

**Легенда:** `[ ]` не начато · `[~]` в работе · `[x]` готово.
**Где остановились:** _Все Фазы 0–5 закрыты: 4/5 транспортов (REST/gRPC/AMQP/Kafka), QR-подпись,
batch, async jobs, OIDC-вход по ЭЦП — работают end-to-end в UI на реальных ключах. Добавлен
**observability-стек**: Prometheus (:9095) скрейпит `qoltanba:9090` + shipped alert-rules,
Grafana (:3002, анонимный admin) с авто-провижном дашборда `qoltanba-overview` и датасорсов
Prometheus/Loki, Loki (:3100) + Promtail (docker-SD, JSON-логи сервиса). Ассеты —
копии канонических из `../../../deploy/observability/` (см. `deploy/observability/README.md`).
Открыто лишь: NATS round-trip (server-side JS-push, вне песочницы) и косметика (QR-auth-режим,
NDJSON-стриминг в UI)._

## Как запустить

```
docker compose -f playground/compose.yaml up -d --build
```
UI — http://localhost:5174 · BFF — :5173 · REST :8080 · gRPC :9091 ·
health/metrics :9090 · RabbitMQ UI :15672 · Redpanda console :8088 · NATS :8222.
Все образы собраны, `qoltanba` — healthy, стек проверен живьём.

---

## Статус фаз

- [x] **Фаза 0 — каркас + gitignore.** `/playground/` в `.gitignore`; скелет создан.
- [x] **Фаза 1 — compose + брокеры.** qoltanba (все транспорты) + RabbitMQ/Redpanda/NATS
  (+UI), провижн очереди/стрима/топиков, монтаж native/ключей. **Kalkan реально грузится**
  (self-test ok). Дым: REST `verify` valid=true на реальном ключе — пройден.
- [x] **Фаза 2 — TS-SDK.** REST (`openapi-typescript`+`openapi-fetch`) и gRPC
  (`ts-proto`+`@grpc/grpc-js`) сгенерированы, типизируются. Регенерация — `npm run gen -w @qoltanba/sdk`.
- [x] **Фаза 3 — BFF.** Fastify-веер по всем транспортам, нормализованный конверт,
  каталог тестовых ключей, проброс observability. Типизируется, образ собран.
- [x] **Фаза 4 — фронт.** React+Vite+Tailwind+shadcn-компоненты: операции, переключатель
  транспорта, выбор ключа, JSON-редактор с шаблонами, вьюеры (карточка серта/цепочка/
  ревокация/тайминги), режим сравнения транспортов, health-индикатор, тема. Собирается (vite), образ поднят.

## Что подтверждено живьём (реальный Kalkan + реальные ключи)

**4 из 5 транспортов — полный sign+verify round-trip** (`valid=true`, signer `CN=ТЕСТОВ ТЕСТ`):

- **REST** ✓
- **gRPC** ✓
- **AMQP (RabbitMQ)** ✓ — полный MQ request/reply
- **Kafka (Redpanda)** ✓ — полный MQ request/reply (после Snappy-фикса)
- **NATS** ✗ — заблокирован server-side (JS-push → reply на ACK-subject); BFF честно таймаутит.
- **cert-info** по `KeySpec.path` — парсит серт, ИИН, роли (все транспорты). ✓

> **gRPC был не сломан.** Прежние «детерминированные» gRPC-сбои (`code=3`) — это
> **деградация нативного состояния под миксом операций** (Kalkan-флейк, см.
> [`../../kalkan-native-flake.md`](../../kalkan-native-flake.md)): shared-пул (PoolSize=1)
> накапливает порчу процесс-глобального состояния, операции начинают отказывать до
> **рестарта**. На свежем контейнере REST/gRPC/AMQP работают все. Это gotcha песочницы,
> а не транспорта.

---

## Открытые вопросы (для следующих сессий)

- [x] **gRPC sign/verify** — РАБОТАЕТ. Прежние сбои = native-флейк (деградация shared-пула
  под миксом операций), не баг gRPC. См. заметку выше.
- [x] **Kafka — РАБОТАЕТ.** Причина была: qoltanba (franz-go) сжимает ответы **Snappy**, а
  `kafkajs` его не декодирует из коробки (`KafkaJSNotImplemented: Snappy` → консьюмер джойнится,
  но фетч падает → 0 сообщений). Фикс: pure-JS Snappy-кодек (`snappyjs`) зарегистрирован в
  `bff/src/transports/kafka.ts` (импорт `CompressionCodecs` — только через default-импорт
  kafkajs, он CJS и не отдаёт этот named-export под ESM). Подтверждено sign+verify round-trip.
- [ ] **extract** — не ошибается, но `content=null`: `core.Extract` не форвардит `InputPEM`
  (PEM-подпись читается как DER) и не просит извлечение контента у провайдера. Service-нюанс,
  не песочница. Для DER-подписи extract отрабатывает без ошибки.
- [ ] **NATS — round-trip таймаутит** (ожидаемо, единственный незакрытый транспорт). При JetStream **push**-доставке
  `msg.Reply` = ACK-subject `$JS.ACK…`, поэтому сервис публикует ответ туда, а не в инбокс/
  фикс-reply-subject (`internal/transport/nats` берёт `m.Reply` раньше `cfg.ReplySubject`).
  Это дизайн-нюанс сервиса; BFF показывает таймаут честно. Решать server-side (pull-consumer
  или чтение reply-subject из заголовка) — вне песочницы.
- [x] **QR-песочница (профиль agnostic, режим sign)** — работает end-to-end. BFF: proxy
  create/poll + симулятор eGov-приложения (`GET /qr/a/{id}` → sign → `POST /qr/a/{id}`). Фронт:
  вкладка «QR sign», рендер QR-PNG (сервис сам отдаёт PNG в поле `qr`), поллинг до `verified`,
  карточка подписанта. Подтверждено: `status=verified`, signer `ТЕСТОВ ТЕСТ`, `iin=123456789011`.
- [x] **Batch + async jobs (UI)** — вкладка «Batch & Jobs». Batch: N sign-элементов одним
  вызовом (агрегированный ответ `{total,succeeded,failed,results[]}`), сетка результатов. Async:
  submit `POST /jobs` → поллинг `GET /jobs/{id}` до terminal → `GET /jobs/{id}/result`. BFF:
  `bff/src/bulk.ts`. Подтверждено: batch 3/3 ok, job queued→succeeded→result.
- [x] **OIDC «login with ЭЦП» (UI)** — вкладка «OIDC login». BFF (`bff/src/oidc.ts`) прогоняет
  весь grant `urn:qoltanba:params:grant-type:ecp` server-side: challenge → detached-подпись nonce
  выбранным ключом → verify → RS256 id_token/access_token; декодирует id_token, зовёт /userinfo.
  Включено: `OIDC_ENABLED` + `OIDC_ISSUER` (эфемерный RS256-ключ, `REQUIRE_OCSP=false`).
  Подтверждено: id_token выдан, клеймы (ИИН/имя/роли) извлечены.
- [x] **Прод-крипта своим реальным ключом** — `compose.prod.yaml` (RK-registry якоря без
  test-roots, AIA, verify-chain, require-ocsp, дефолтный TSA, снят test-CA). Запуск:
  `docker compose -f playground/compose.yaml -f playground/compose.prod.yaml up -d`. Подача ключа:
  (а) загрузка `.p12` inline в Operations (`uploadP12` в `App.tsx`, `withInlineKey`); (б) вкладка
  **NCALayer** (`NcaLayerPage.tsx` + `lib/ncalayer.ts`): подпись через `wss://127.0.0.1:13579`
  (`createCAdESFromBase64`, detached), верификация на сервере. BFF `verifysig.ts` — устойчивая
  верификация (DER, затем PEM-обёртка) `/api/verify-signature`. **Прод-путь тестируется только на
  машине пользователя** (реальный ЭЦП + NCALayer + сеть к pki.gov.kz). **Операторский runbook —
  `playground/PROD.md`** (запуск, .p12/NCALayer пошагово, таблица прод-настроек, траблшутинг).
- [ ] QR **auth**-режим (QR-вход вместо sign) — сервер готов (oidc включён), в UI не выведен;
  NDJSON-стриминг batch и стриминг gRPC `*Batch` — не выведены (используется агрегированный режим).

## Находки, вынесенные в durable-доки/факты

- **Runtime-образ обязан быть `golang:1.25-bookworm` (не `debian:bookworm-slim`).** На slim
  GOST-подпись приватным ключом падает `KCR 0x08F00040`, хотя чтение серта/verify работают;
  fuller-bookworm (как в `test/functional`) — подписывает. Зафиксировано в `qoltanba.Dockerfile`.
- **qoltanba завершает весь процесс, если первый dial MQ-консьюмера отклонён** (errgroup:
  ошибка любого транспорта гасит сервис). Поэтому брокеры должны быть **полностью** готовы
  до старта — RabbitMQ healthcheck = `check_port_connectivity` (не `ping`, который проходит
  до открытия 5672). → gotcha в [`index.md`](index.md).
- **MQ-конверт** (`internal/transport/mq`): запрос `{op, correlationId, request}` → ответ
  `{correlationId, op, result|error}`; batch — по сообщению на элемент. Reply-routing: AMQP
  reply-to, Kafka заголовок `reply-topic`/`kalkan.replies`, NATS reply-subject.
- **Тестовые серты требуют `noCheckCertTime`** для sign без trust-store — иначе `0x08F00042`.
  Зашито в шаблоны запросов фронта (`sign`: +`outputPem`; `verify`/`extract`: +`inputPem`).
- **Строгий verify (`CheckCertTime=true`) требует загруженного trust-anchor**, иначе `valid=false`
  даже для серта, валидного по датам. **QR-verify форсит `CheckCertTime=true`** → без CA QR всегда
  `failed`. Фикс: тестовые CA (`native/keys-and-certs/CA_Test/*.cer`, они **DER**) сконвертированы
  DER→PEM в `playground/ca/` и смонтированы как `QOLTANBA_TRUST_CA_DIR` (+`TRUST_VERIFY_CHAIN`).
  `trust.LoadDir` читает только PEM (`.pem/.crt/.cer`, но парсит как PEM) и **не рекурсивно**.
- **DER-путь Kalkan неполон — работает только PEM.** `sign` с `outputPem:false` возвращает
  **пустую** подпись; `verify` DER (`inputPem:false`) даёт `valid=true`, но `signers=0`. Поэтому
  везде используем `outputPem:true`/`inputPem:true`. QR-оркестратор сам сниффит PEM (`looksPEM`),
  так что «телефон» шлёт base64(PEM), а не сырой DER.
- Хост-порт фронта — **5174** (3000 был занят).
- **`VITE_BFF_URL` в `api.ts` — через `||`, не `??`.** Docker задаёт ARG-backed ENV пустой
  строкой при отсутствии значения; `??` пропускает `""` → запросы уходят same-origin в nginx
  (:5174), а не в BFF (:5173) → «unreachable». `||` ловит пустую строку и берёт дефолт.
