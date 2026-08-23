# Транспорты: CLI, REST, socket, gRPC, MQ

Часть фичи `service-platform` — сначала [`index.md`](index.md).
Все транспорты — **тонкие адаптеры** над `core`: декодировать запрос → вызвать
доменный сервис → закодировать ответ. Никакой крипто-логики (правило слоёв —
[`../../architecture.md`](../../architecture.md)). Каждый включается отдельно
конфигом (см. [`observability-security.md`](observability-security.md) и `--http`/
`--grpc`/… флаги).

## Матрица транспортов

| Транспорт | Библиотека | Модель |
|-----------|-----------|--------|
| CLI ✅ | stdlib `flag` | процесс: op-аргумент + JSON в stdin → JSON в stdout |
| HTTP REST ✅ | stdlib `net/http` (mux Go 1.22, паттерны `POST /sign`) | тот же `http.Server` слушает TCP **или** Unix-socket |
| Unix-socket / named pipe ✅ | как REST/gRPC | локальный IPC без сетевого порта (`addr` вида `unix:/путь`) |
| gRPC ✅ | `google.golang.org/grpc` | типизированный контракт **`api/qoltanba/v1/service.proto`** (TCP или unix) |
| RabbitMQ ✅ | `rabbitmq/amqp091-go` | consume job → publish в reply-to/reply-queue по `correlationId`; **ack после публикации результата** |
| Kafka ✅ | `twmb/franz-go` | consumer group → reply-topic по ключу=`correlationId`; **commit offset после успеха** |
| NATS ✅ | `nats-io/nats.go` | JetStream: durable consumer → reply-subject; **ack после публикации результата** |

✅ — реализовано (все транспорты). REST/CLI — на **stdlib** (`net/http` mux 1.22 и
`flag`), а не `chi`/`cobra`, — в духе «тонкий/без раздувания»; при росте
маршрутизации/подкоманд их можно добавить, не меняя домен. Единый JSON-контракт
REST/CLI — в общем пакете `internal/transport/dto` (запрос→доменный вход; ответ —
доменные output-типы напрямую).

**Общий диспетчер (`internal/transport/dispatch`).** Не-HTTP транспорты (CLI + все
MQ) маршрутизируют «имя операции + JSON-payload → доменный вызов» через один
`dispatch.Handle`: одна карта `op→core`, один список `Ops`. HTTP/gRPC маппятся
по пути/proto, но формы полей те же (`dto`). Это убирает дублирование логики
разбора между CLI и брокерами.

**gRPC** намеренно завязан на **новый фокусный `api/qoltanba/v1/service.proto`**
(реализованные операции, зеркалит доменные типы), а **не** на черновой
`api/qoltanba-draft.proto` (тот помечен «не завязываться на имена полей»). Маппинг
proto↔домен — в `internal/transport/grpc` (сгенерённый код — `*.pb.go` рядом с
proto; плагины `protoc-gen-go`/`-go-grpc`). Включается `--grpc` (адрес `--grpc-addr`,
дефолт `:9091`, TCP или `unix:/путь`), рядом с REST — общий сервис-инстанс, общий
graceful shutdown *(nascent)*.

Один HTTP-сервер обслуживает и TCP, и Unix-socket (`http.addr` вида `unix:/путь`) —
отдельного транспорта под socket нет, это режим прослушивания REST/gRPC.

**Webhook — не отдельный транспорт.** Он раскладывается на уже существующее:
*входящий* webhook (чужая система шлёт «подпиши/проверь») = обычный REST-эндпоинт
`POST /sign|/verify`; *исходящий* webhook = `callbackUrl` доставки результата
async-задания (см. [`batch-async.md`](batch-async.md)). Отдельный канал не заводим —
нужны лишь стабильный HTTP-контракт и аутентификация входящего вызова.

## REST-эндпоинты (v1)

Синхронные операции (единичный вызов = пакет из одного, см. [`batch-async.md`](batch-async.md)):

- `POST /sign` — подпись (формат CMS/XML/WSSE/ZIP в запросе).
- `POST /sign/add` — со-подпись: добавить подпись к существующему контейнеру.
- `POST /verify` — проверка + исчерпывающее извлечение подписантов/цепочки/валидности.
- `POST /extract` — восстановить оригинал из attached-подписи.
- `POST /cert/info` — полный разбор сертификата (+ опц. цепочка/валидация).
- `POST /cert/validate` — валидация по цепочке (OCSP/CRL).
- `POST /verify/at` — валидация на момент времени; `POST /sign/archive` — вложить
  LTV-доказательства (CAdES-LT).
- Пакетные: `POST /{op}/batch` + `POST /verify/registry` (сводный реестр); async:
  `POST /jobs` → `GET /jobs/{id}` → `GET /jobs/{id}/result` (см.
  [`batch-async.md`](batch-async.md)).

Прикладные потоки за своими флагами: `/oidc/*` + `/jwks.json` ([`oidc.md`](oidc.md)),
`/qr/sessions` ([`qr.md`](qr.md)), `/qr/documents` (подписанный QR), `/challenge`,
`/multisign/sessions`, `/audit/*`, HTML-поверхности `/verify/portal` и `/console`,
`/sandbox/sign`.

Health/метрики — отдельные эндпоинты, порт может быть отделён от рабочего (см.
[`observability-security.md`](observability-security.md)).

**Исчерпывающая карта REST — `api/openapi.yaml`**, генерируемая `tools/openapigen`
(`make openapi`) вместе с Postman-коллекцией. Схемы рефлексятся из Go-типов, но
**пути объявляются руками** в `tools/openapigen/spec.go` — поэтому `make check-generated`
(он лишь перегенерирует и диффает) не способен заметить эндпоинт, который в таблицу не
внесли. Это ловит `tools/openapigen/spec_test.go`: он вычитывает `mux.HandleFunc` из
`internal/transport/rest` через AST и падает, если маршрут не задокументирован (или
задокументированный путь больше не обслуживается). Там же сверяется список
`idempotentPaths` с реально обёрнутыми в middleware хендлерами. Durable-семантика
контракта — [`../signature-service/data-contract.md`](../signature-service/data-contract.md).

## Асинхронные транспорты (Rabbit/Kafka/NATS)

MQ естественно асинхронны: один job = один элемент (либо job-конверт с массивом),
`correlationId`/`jobId` на элемент. Общие правила:

- **Идемпотентность по `correlationId`/`jobId`** — повтор доставки (at-least-once)
  не должен приводить к повторной работе.
- **Конкурентность ограничена пулом воркеров** — MQ-консюмер берёт слот из того же
  пула, что и синхронные вызовы (`mq.Semaphore` размером `workers`); это удерживает
  RAM и защищает нативную либу.
- **Порядок подтверждения:** Rabbit — `ack` только после публикации результата
  (иначе `Nack`+requeue); Kafka — commit offset только после того как **все** записи
  поллинга опубликовали ответ (иначе весь батч переисполняется); NATS — `Ack` только
  после публикации. Иначе потеря задания при сбое.
- **Ретраи/DLQ — по политике потребителя** (не навязываем свою). Бизнес/валидационная
  ошибка кодируется в конверт-ответ (`error.kind`) и всё равно подтверждается — повтор
  её не исправит; переисполняется только то, что не удалось **опубликовать**.
- **Брокер/стрим не создаём** — очередь (Rabbit), топик+consumer-group (Kafka), стрим
  под subject (NATS JetStream) провижнит потребитель. Мы — клиент (BYO-инфраструктура,
  в духе «не бандлим брокер», см. [`batch-async.md`](batch-async.md)).
- **Трейс-контекст** (`traceparent`/`correlationId`) пробрасывается через MQ, а не
  только HTTP — см. [`observability-security.md`](observability-security.md).

### Envelope-контракт MQ (`internal/transport/mq`)

Тело сообщения — не транспортные заголовки — несёт контракт, чтобы форма была
одинаковой у всех брокеров независимо от их метаданных. Один `mq.Processor.Process`
декодирует конверт, вызывает `dispatch.Handle`, кодирует конверт-ответ; брокерные
адаптеры (`amqp`/`kafka`/`nats`) — тонкие, владеют только сетевым I/O.

- **Запрос:** `{ "op": "verify", "correlationId": "…", "request": { …тот же JSON, что REST/CLI… } }`.
- **Ответ:** `{ "correlationId": "…", "op": "…", "result": {…} }` **либо**
  `{ …, "error": { "kind": "invalid|unsupported|unavailable|canceled|internal", "code": "0x08F…", "message": "…", "action": "…" } }`
  — `message`/`action` из дружелюбного каталога ошибок (тот же, что и в `libError`;
  см. [`../signature-service/data-contract.md`](../signature-service/data-contract.md)).
- **`correlationId`:** значение из конверта, иначе — транспортно-нативный id
  (AMQP `correlation_id`, Kafka record key, NATS `Nats-Msg-Id`); эхом идёт в ответ и
  ставится на исходящее сообщение.
- **Адрес ответа:** AMQP `reply-to` сообщения (иначе фикс. `amqp.reply-queue`); Kafka
  заголовок `reply-topic` (иначе `kafka.reply-topic`); NATS `Reply`-subject (иначе
  `nats.reply-subject`). Нет адреса → fire-and-forget (обработали и подтвердили).

## Идемпотентность (безопасные ретраи)

Общий node-local кэш (`internal/idempotency`: single-flight + TTL + LRU, **кэширует
только успехи**) под всеми транспортами; включается `idempotency.enabled` (ttl 24h,
max-entries 8192 по умолчанию). Один инстанс кэша делят REST и MQ (обвязка в `main`).

- **REST:** заголовок `Idempotency-Key` на мутирующих endpoint-ах (sign/verify/verify-at/
  extract/cert-*, включая batch). Повтор с тем же ключом **реплеит** первый успешный
  (2xx) ответ и ставит `Idempotency-Replayed: true`; не-2xx и транзиентные не кэшируются
  (ретрай пере-выполняется). Ключ неймспейсится `method+path`. Нет заголовка/кэша —
  прозрачный passthrough.
- **MQ:** поле конверта `idempotencyKey`. Для **single-op** at-least-once redelivery
  реплеит первый ответ (кэшируется только `result`, `correlationId` подставляется свежий);
  **batch** стримятся и не дедупятся.
- **Async-jobs:** `Manager.SubmitIdempotent` (REST `POST /jobs` — тело `idempotencyKey`
  или заголовок `Idempotency-Key`; MQ `job-submit` — поле конверта): повтор с тем же ключом
  отдаёт **существующий** job, не создаёт дубль. Дедуп-мэп node-local, best-effort,
  bounded (oldest-eviction), stale-маппинги (reaped job) чистятся лениво.

- **gRPC:** metadata `idempotency-key` (не поле в proto) — см. «Паритет gRPC» ниже.

Граница честная: **node-local, in-memory** — защита от ретрая клиента/брокера, не от
гонки между инстансами (для этого нужен общий стор — вне scope).

### Конфиг MQ

Транспорт включается **самим фактом задания** строки подключения (отдельного
`enabled`-флага нет): `amqp.url` / `kafka.brokers` / `nats.url`. Валидация требует
целевую точку: `amqp.queue`; `kafka.topic`+`kafka.group`; `nats.subject`+`nats.durable`.
`amqp.url`/`nats.url` помечены секретами (редактируются в `config dump`). Полный
перечень ключей — реестр `internal/config`.

## Паритет gRPC (закрытые хвосты)

- **`rpc VerifyAt`** — валидация на момент времени теперь есть и в gRPC
  (`VerifyAtRequest`/`VerifyAtResponse` + `PointInTimeVerdict`, `SignerAt`).
  Регенерация: `protoc --go_out --go-grpc_out` по `api/qoltanba/v1/service.proto`.
- **Idempotency в gRPC — через metadata `idempotency-key`**, а не поле в proto:
  ключ описывает *доставку*, а не операцию (as-least-once повторяет то же
  сообщение), поэтому контракт остаётся чистым, а поведение совпадает с REST-
  заголовком. Реплей собирает ответ из `protoregistry` по имени типа и **не
  вызывает обработчик заново**. Стримовые батчи не покрыты намеренно.
- **`rpc Archive`** — LTV-архив теперь есть и в gRPC (`ArchiveRequest`/`ArchiveResponse`
  + `ArchiveEvidence`), включая `allow_revoked`. Это была единственная доменная
  операция из `dispatch.Ops`, которой у gRPC не хватало.
  > **Граница паритета.** Паритет меряется по `dispatch.Ops` — операциям домена,
  > одинаковым на всех stateless-транспортах. Прикладные фичи с состоянием и
  > собственным жизненным циклом (`/challenge`, `/multisign/sessions`, `/audit/*`,
  > `/qr/*`, `/verify/registry`, HTML-поверхности) — **REST-ресурсы by design**, а не
  > пробел в gRPC: у них ресурсные URL, коды 201/204/409, NDJSON-стриминг и
  > content-negotiation, которые в RPC-контракт не переносятся один-в-один. Тянуть их
  > в proto — не паритет, а вторая параллельная поверхность.
- **Рендер ошибок:** generic-запись каталога («библиотека вернула ошибку») теперь
  применяется только к ошибкам, реально пришедшим из библиотеки. Для отклонённого
  запроса домена показывается его собственный текст — раньше конкретное и верное
  сообщение подменялось расплывчатым и неверным.
