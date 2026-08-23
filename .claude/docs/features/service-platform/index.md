# Сервисная платформа вокруг крипто-ядра — обзор

**Scope.** Рантайм-обвязка сервиса подписи/проверки: транспорты, пакетный и
асинхронный режимы, источники ключей, наблюдаемость, гигиена секретов,
конфигурация. Крипто-домен (sign/verify, разбор сертификата, валидация) —
вне этого дока → [`../signature-service/index.md`](../signature-service/index.md).
Слои и правило зависимостей — [`../../architecture.md`](../../architecture.md).

> **Слои зафиксированы, наполнение — нет.** Целевая раскладка (драйвер/домен/
> транспорт/инфраструктура, ports & adapters) — в [`../../architecture.md`](../../architecture.md);
> этот док фиксирует durable-дизайн платформы (модели, политики, семантику),
> переживающий реализацию. Ссылки на app-код помечены *(nascent)*.

## Взгляд с высоты

Одно транспортно-независимое ядро (`core`), вокруг которого — тонкие адаптеры и
инфраструктура за интерфейсами домена:

```
  CLI ─┐
 REST ─┤                                          ┌─ KeySource (источник ключа)
  UDS ─┤   транспорты      core.Service           ├─ trust-store / CA-реестр РК
 gRPC ─┼──► (маппинг)  ──► (Go-структуры,   ──────┤
Rabbit┤                     оркестрация)          ├─ observability (health/метрики/логи)
Kafka ┘                          │                └─ config (флаги+env+файл)
                                 ▼
                          Provider (FFI, пул воркеров) → нативная Kalkan
```

Каждый транспорт **включается отдельно** (не включён — RAM не тратит) и несёт
**только маппинг** запрос↔домен, без крипто-логики. Все операции доступны из всех
транспортов через **единый контракт**, в единичном и пакетном варианте, синхронно
и как async-задание для больших файлов.

## Позиционирование и режимы деплоя

Признак, по которому расходятся сценарии внедрения, — **где живёт приватный ключ**:

- **Client-side (ключ у пользователя).** Конечный пользователь подписывает так, что
  приватный ключ **не покидает его устройство** — двумя способами: **NCALayer**
  (десктопный мост, локальный WebSocket) и **QR-подписание через eGov Mobile**
  (приложение сканирует QR, качает данные по одноразовому URL, возвращает подпись).
  В обоих случаях сервис в самой подписи **не участвует**: его роль — серверная
  проверка. **NCALayer/eGov Mobile не проксируем и не заменяем.** Важный факт: их
  подпись — тот же CMS/XML/WSSE, что и серверная, поэтому `POST /verify` проверяет её
  **один-в-один, независимо от происхождения** — QR-верификация у нас уже покрыта
  без новой крипто-работы.
- **Server-side (ключ у сервиса).** Серверный орг-ключ (печать организации) через
  `KeySource` — массовая/пакетная подпись счетов, актов, e-gov пакетов.

**Оркестрация QR-сессии — не крипто, а опциональный транспорт (при спросе).** Само
QR-подписание client-side, но бэкенду нужен «оркестратор»: сформировать eGov-mobile
JSON + QR, завести одноразовую TTL-сессию с публичным URL, отдать данные и принять
подпись → сразу `verify`/`extract`. Это доменно-тонкий адаптер рядом с REST/gRPC,
**не** sign-эндпоинт. Официальный путь требует **Smart Bridge** у потребителя; обход
— relay-сервис (напр. SIGEX, open-source). **Свой relay не поднимаем** (чужой сервис,
противоречит BYOL) — см. не-цели в [`../../architecture.md`](../../architecture.md).

**Verification-only** — первоклассный режим деплоя, включаемый **флагом конфига**
(тот же бинарь): ключевой путь целиком отключён — нет `KeySource`, нет `sign`-
эндпоинтов, только `verify`/`cert/info`/`cert/validate`. Ноль работы с секретами →
снимает половину требований гигиены секретов, безопасен в открытом периметре.
Самый массовый сценарий (принять и проверить чужой подписанный документ).

**Дистрибуция (главный рычаг внедряемости, важнее числа транспортов):**
- **Нативный бинарь — первичный артефакт, Docker — один из вариантов.** Go даёт один
  исполняемый файл на ОС/архитектуру; контейнер лишь удобная обёртка над окружением,
  не требование (у многих серверов — 1С/Windows Server, легаси-VM — Docker нет).
  Каветы из-за cgo: сборка **под каждую цель отдельно** (Linux x64, Windows x64/x86;
  Windows — mingw), и **бинарь обязан быть glibc, не musl/static** — Kalkan-либа
  glibc-сборки грузится `dlopen` в тот же процесс, две libc в одном процессе рушат
  его; для широкой совместимости собирать против старого базового glibc. Настройка
  загрузчика (OpenSSL-1.1-форк vs системный OpenSSL-3) — тем же `LD_PRELOAD`/lib-path
  (Linux) или DLL рядом с `.exe` (Windows), в идеале **бинарь ставит это сам**;
  механика — [`../signature-service/native-library.md`](../signature-service/native-library.md),
  [`../../kalkan-api/loading.md`](../../kalkan-api/loading.md). **BYOL не меняется:** ни
  бинарь, ни образ не несут Kalkan — потребитель даёт `--lib-path`. Конкретные форматы
  пакетов (tarball+systemd / zip+Windows-service, `.deb`/`.rpm`/MSI) — кандидаты
  ([`../../roadmap.md`](../../roadmap.md)).
- **OCI-образ с BYOL-mount** — образ несёт окружение (OpenSSL-1.1, iconv,
  `LD_PRELOAD`-обвязка из `test/functional/run.sh`), потребитель монтирует `native/`
  volume'ом. Удобно там, где Docker уже есть.
- **Генерируемые клиенты** из `api/qoltanba-draft.proto` (gRPC: JS/TS, Java, Python, PHP,
  C#) + **OpenAPI** для REST — снимают трение внедрения в разнородные системы.

**Три оси нагрузки, которые платформа держит под контролем:**
- **Параллелизм** — крипто-вызовы сериализованы через пул воркеров (нативная либа
  не тред-безопасна, см. [`../signature-service/native-library.md`](../signature-service/native-library.md)).
  N воркеров ограничивает и параллелизм, и RAM, и нагрузку от MQ-консюмеров.
- **Размер входа** — большие файлы идут по ссылке (путь/URL), не inline base64;
  async-задания + потоковая обработка (`KC_IN_FILE`/hash-streaming/detached).
- **Размер пакета** — batch-лимит + отдельная очередь больших заданий +
  backpressure.

## Gotchas (durable-решения, не выводятся из кода)

- **Единичный вызов = пакет из одного элемента.** Общий кодовый путь, единый
  контракт — не плодим отдельную логику для «одного». См. [`batch-async.md`](batch-async.md).
- **Индекс подписи не несёт смысла** (≠ порядок подписания, различается CMS/XML) —
  контракт это фиксирует; детали — [`../signature-service/signing-verify.md`](../signature-service/signing-verify.md).
- **Секреты только во входе.** Пароль/PIN/inline-`p12`/подписываемые данные (могут
  быть ПДн) не попадают в ответы, логи, метрики (значения и лейблы), трейсы, тела
  ошибок, `/statusz`, дампы конфига. Сквозное правило — [`observability-security.md`](observability-security.md).
- **Inline-ключ — только по TLS/локальному сокету.** Секрет в теле запроса требует
  защищённого транспорта; см. [`keysource.md`](keysource.md).
- **Readiness завязан на самотест библиотеки**, а не только на «процесс жив» —
  трафик не принимается до успешной загрузки+самотеста Kalkan (health-модель —
  [`observability-security.md`](observability-security.md)).
- **Async и batch — разные оси, комбинируются:** пакет может исполняться как
  задание; большой элемент внутри пакета — обрабатываться потоково.
- **Крипта живёт в дочерних процессах, сервис библиотеку не грузит.** Сервис
  пере-запускает свой бинарь (`qoltanba crypto-worker`) и гоняет там весь
  `provider.Provider`: библиотека течёт (~1 МБ на verify CMS) и портит свои
  глобалы на вердикте `revoked`, а изнутри процесса это не откатывается. Ребёнок
  рециклится по бюджету операций/RSS и после `revoked`, респавнится после краха
  (вызов повторяется), убивается по таймауту. Оператору это стоит одного процесса
  на воркер (память, `TasksMax`), зато потребление ограничено сверху. Замеры —
  [`../../kalkan-native-flake.md`](../../kalkan-native-flake.md) и
  [`../../kalkan-memory-leak.md`](../../kalkan-memory-leak.md).
- **Брокер не бандлим — durability лестницей.** Чтобы задания не терялись при
  рестарте/деплое, не поднимаем свой Rabbit, а даём встраиваемый on-disk `JobStore`
  (`bbolt`); внешний брокер/стор — опция потребителя. См. [`batch-async.md`](batch-async.md).

## Куда идти дальше

| Под-область | Файл | Триггеры |
|-------------|------|----------|
| Транспорты (CLI/REST/socket/gRPC/Rabbit/Kafka/NATS), REST-эндпоинты, MQ-семантика | [`transports.md`](transports.md) | REST, gRPC, socket, Unix, amqp, kafka, nats, webhook, эндпоинт, correlationId, DLQ, chi |
| Пакетный режим и async-задания для больших файлов | [`batch-async.md`](batch-async.md) | batch, пакет, job, jobId, 202, webhook, callback, durable, JobStore, bbolt, потоковая, backpressure, стриминг, NDJSON |
| Источники ключей (`KeySource`): inline/path/keyId/token/builtin | [`keysource.md`](keysource.md) | KeySource, p12, PKCS12, PIN, токен, kaztoken, keystore, keyId, Vault |
| OIDC-провайдер «вход по ЭЦП»: challenge/verify/token, discovery/JWKS/userinfo | [`oidc.md`](oidc.md) | oidc, openid, discovery, jwks, id_token, access_token, challenge, nonce, RS256, userinfo, well-known, Socialite, login по ЭЦП |
| QR-оркестратор eGov Mobile: сессия, профили (agnostic/egov/relay), sign/auth, base64-QR | [`qr.md`](qr.md) | qr, egov mobile, egovmobile, egov business, подписание, sign, deeplink, launch link, SIGEX, Smart Bridge, documentsToSign, signMethod, relay, capability-URL, X-Forwarded, public-base-url |
| Наблюдаемость + гигиена секретов | [`observability-security.md`](observability-security.md) | health, readyz, statusz, метрики, Prometheus, slog, трейсинг, OTel, секрет, редакция, аудит |

## Карта файлов

**Живой контракт (код, источник истины формы):**

- `qoltanba/api/qoltanba-draft.proto` — gRPC-контракт всех операций; JSON-зеркало для
  REST/socket/CLI/MQ. **Драфт**: имена/составы полей уточняются. Durable-семантику
  контракта (кодировки, best-effort, `libError`, секреты) держит
  [`../signature-service/data-contract.md`](../signature-service/data-contract.md).

**App-код (nascent):** транспорты `transport/*` (по адаптеру на транспорт),
инфраструктура за интерфейсами домена — `KeySource`, trust-store (`internal/pki`),
observability, config, `internal/cryptoworker` (драйвер вне процесса: протокол,
супервизор дочерних процессов, реализация `Provider` поверх них). Границы и правило зависимостей — [`../../architecture.md`](../../architecture.md).

## Связанные доки

- [`../../architecture.md`](../../architecture.md) — слои, правило зависимостей, границы проекта, тесты.
- [`../signature-service/index.md`](../signature-service/index.md) — крипто-домен (sign/verify/cert/validate).
- [`../signature-service/data-contract.md`](../signature-service/data-contract.md) — durable-семантика запрос/ответ.
