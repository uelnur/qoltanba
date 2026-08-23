# Dev-песочница (playground) — обзор

**Scope.** Вспомогательный **дебаг-инструмент** для ручной игры с сервисом на
**реальных ключах**: один `docker compose`, поднимающий `qoltanba` со **всеми**
транспортами, брокеры (RabbitMQ/Kafka/NATS), TS-BFF (веер по транспортам) и
современный веб-фронт. **Не продукт, не деплой-артефакт** — живёт в
**gitignored** `playground/` (код) и держит durable-знание здесь. Продовый
деплой (committed) — `deploy/compose.yaml`, его не трогаем. Фазовый план и статус
работ → [`plan.md`](plan.md).

> **Код песочницы — под gitignore, дока — в репозитории.** `playground/**`
> игнорируется (см. корневой `.gitignore`); эта дока — единственный durable-след
> и точка продолжения между сессиями. Ссылки на app-код помечены *(nascent)* до
> его появления.

## Взгляд с высоты

Одна операция (sign/verify/…) прогоняется через **выбранный транспорт**, а BFF
возвращает **нормализованный дебаг-конверт** (запрос, ответ, сырой wire, латентность,
метаданные транспорта). Ценность инструмента — увидеть *одну и ту же* операцию
через все транспорты рядом.

```
  browser (React+Vite+Tailwind+shadcn)
      │  выбор: операция · транспорт · ключ · вход
      ▼
  BFF (TS/Fastify) ── нормализованный конверт {transport, req, resp, rawWire, latencyMs}
      ├── REST   ──► qoltanba :8080   (openapi-fetch, из api/openapi.yaml)
      ├── gRPC   ──► qoltanba :9091   (@grpc/grpc-js + ts-proto, из service.proto)
      ├── AMQP   ──► RabbitMQ ──► qoltanba
      ├── Kafka  ──► Kafka    ──► qoltanba
      └── NATS   ──► NATS     ──► qoltanba
                         │
             qoltanba (BYOL: native/linux-x64 + native/keys-and-certs смонтированы)
```

**BFF — сердце инструмента, а не тонкий прокси.** Он держит клиентов ко всем
транспортам (REST/gRPC через сгенерированный SDK; MQ через `amqplib`/`kafkajs`/
`nats.js`) и приводит любой ответ к единому конверту, чтобы фронт был
транспортно-агностичен. Фронт про gRPC/брокеры не знает — только про BFF.

## Ключевые решения (зафиксированы)

- **Охват транспортов:** все сразу — REST, gRPC, AMQP(RabbitMQ), Kafka, NATS (+CLI
  опционально). Каждый включается в `qoltanba` отдельным флагом/URL (см. `.env.example`).
- **Фронт:** React + Vite + TypeScript + Tailwind + shadcn/ui; сборка — статикой под nginx в compose.
- **BFF:** TypeScript (Node/Fastify), веер по транспортам, единый дебаг-конверт.
- **SDK:** генерируем TS-клиент — REST из `api/openapi.yaml` (`openapi-typescript` +
  `openapi-fetch`), gRPC из `api/qoltanba/v1/service.proto` (`ts-proto` + `@grpc/grpc-js`;
  Node-сторона, поэтому нативный gRPC со стримингом batch/jobs, не grpc-web).

## Gotchas (неочевидное, не выводится из кода)

- **BYOL + платформа.** Kalkan — glibc/amd64; сервис-контейнер обязан быть
  `platform: linux/amd64` и **glibc** (Debian, не Alpine — два libc в одном процессе
  крешат). На Apple Silicon — под эмуляцией. BFF/фронт — нативная арка.
- **Реальные ключи уже лежат в репо (gitignored).** `native/keys-and-certs/` — тестовые
  `.p12` всех профилей НУЦ (valid/revoked, две эпохи), пароль `Qwerty12`, + `CA_Test/`,
  `CRL/`. Монтируем их в `qoltanba`; ключ подаётся как `PathKey` (server-side) либо как
  `InlineKey` (загрузка p12 из UI) — inline требует `QOLTANBA_KEYS_ALLOW_INLINE=true`
  (безопасно только локально/по TLS; в compose — локально).
- **Loader-обвязка нетривиальна.** `qoltanba` требует `libkalkancrypto.so`
  (OpenSSL-1.1-форк), iconv-shim, `libpcsclite`, `libm` при загрузке. Compose-путь —
  `LD_LIBRARY_PATH=/opt/kalkan`; при проблемах смотри рабочую раскладку `LD_PRELOAD` в
  `test/functional/Dockerfile` (эталон механики).
- **Runtime-образ = `golang:1.25-bookworm`, не `debian:bookworm-slim`.** На slim GOST-подпись
  приватным ключом падает `KCR 0x08F00040` (чтение серта/verify при этом работают); fuller-
  bookworm (как в `test/functional`) подписывает. Причина точечно не изолирована — см. `qoltanba.Dockerfile`.
- **qoltanba гасит весь процесс при первом отказе dial MQ-консьюмера** (errgroup: ошибка любого
  транспорта завершает сервис). Брокеры должны быть **полностью** готовы до старта — RabbitMQ
  healthcheck = `check_port_connectivity`, а не `ping` (тот проходит до открытия 5672).
- **MQ-конверт не угадывать.** Формат сообщения для AMQP/Kafka/NATS (поле `op`, payload,
  correlation/reply-to) — durable-факт транспортного слоя; берётся из `internal/transport/mq/`
  и фиксируется в [`../service-platform/transports.md`](../service-platform/transports.md),
  а не переизобретается в BFF.
- **`keyId` не готов.** Из вариантов `KeySpec` (inline/path/token/keyId) `keyId` возвращает
  `ErrUnsupported`; в UI офферим inline/path (token — только с железом).
- **Shared-пул деградирует под миксом операций.** PoolSize=1 (non-isolated) накапливает порчу
  процесс-глобального нативного состояния Kalkan (см. [`../../kalkan-native-flake.md`](../../kalkan-native-flake.md));
  после интенсивного микса sign/verify/cert операции могут начать отказывать до **рестарта**
  `qoltanba`. На свежем контейнере всё работает. Если что-то «сломалось» — `docker compose restart qoltanba`.
- **Kafka: kafkajs + Snappy.** franz-go (qoltanba) сжимает ответы Snappy; kafkajs без кодека
  молча не читает их (джойнится, но фетч падает). BFF регистрирует pure-JS Snappy-кодек.
  `CompressionCodecs`/`CompressionTypes` тянуть только через **default-импорт** kafkajs (CJS).
- **Строгий verify и QR требуют trust-anchor.** `CheckCertTime=true` (и **QR-verify форсит его**)
  делает `valid=false` без загруженного CA, даже для серта, валидного по датам. Тестовые CA
  (`CA_Test/*.cer`, они **DER**) сконвертированы DER→PEM в `playground/ca/` и смонтированы как
  `QOLTANBA_TRUST_CA_DIR`. `trust.LoadDir` парсит только PEM и не рекурсивно.
- **Только PEM-путь Kalkan рабочий.** `sign outputPem:false` → пустая подпись; `verify inputPem:false`
  → `valid=true`, но `signers=0`. Везде `outputPem/inputPem:true`. QR-оркестратор сниффит PEM (`looksPEM`).
- **Дрейф SDK.** `api/openapi.yaml` держит в синхроне CI-гейт `make check-generated`; у proto
  tracked-таргета регенерации нет (`.pb.go` закоммичены руками). TS-SDK регенерим при смене
  контракта — держим npm-скрипт и отмечаем в `plan.md`.

## Карта файлов (nascent — заполняется по мере создания)

Всё под **gitignored** `playground/`:

- `playground/compose.yaml` — единый compose: `qoltanba` (все транспорты) + RabbitMQ/Kafka/NATS
  (+их UI) + `bff` + `frontend`. Отдельный от `deploy/compose.yaml`.
- `playground/.env.example` — включатели транспортов, пути к native/ключам, пароль тестовых ключей.
- `playground/sdk/` — сгенерированный TS-SDK (`rest/` из OpenAPI, `grpc/` из proto) + скрипт регенерации.
- `playground/bff/` — TS/Fastify BFF. Модули: транспорт-адаптеры (`transports/`), `qr.ts` (proxy +
  симулятор eGov-приложения), `oidc.ts` (grant `…:ecp` server-side), `bulk.ts` (batch + async jobs),
  `upstream.ts` (общий REST-хелпер), каталог ключей (`keys.ts`), конверт (`envelope.ts`).
- `playground/frontend/` — React/Vite/Tailwind/shadcn; 4 вкладки (`Header.tsx` `View`): **Operations**
  (операции/транспорты/сравнение), **Batch & Jobs** (`BatchPage.tsx`), **QR sign** (`QRPage.tsx`:
  QR-PNG + Simulate + поллинг), **OIDC login** (`OidcPage.tsx`: вход по ЭЦП → токены/клеймы).
- `playground/ca/` — тестовые CA (DER→PEM) для trust-store (gitignored, генерятся из `native/keys-and-certs/CA_Test`).
- `playground/compose.prod.yaml` — оверрайд «прод-крипта»: RK-registry якоря (без test-roots), AIA,
  verify-chain, require-ocsp, дефолтный TSA, снят test-CA. **Несовместим с тестовыми ключами** —
  только реальный ЭЦП (upload `.p12` inline или NCALayer). Нужна сеть к `pki.gov.kz`.

Источники контракта (committed, читать при генерации/маппинге): `api/openapi.yaml`,
`api/qoltanba/v1/service.proto`, `internal/transport/dto/`, `internal/core/` (типы ответов),
`api/contracts.md`.

## Связанные доки

- [`plan.md`](plan.md) — фазовый план и статус (обновляется каждую сессию).
- [`../service-platform/transports.md`](../service-platform/transports.md) — семантика транспортов, REST-эндпоинты, MQ-конверт.
- [`../service-platform/keysource.md`](../service-platform/keysource.md) — `KeySpec` inline/path/token/keyId.
- [`../signature-service/data-contract.md`](../signature-service/data-contract.md) — семантика запрос/ответ.
- [`../../roadmap.md`](../../roadmap.md) — прикладной вектор (портал верификации, JS-виджет) — с чем песочница перекликается.
