# tools/probe — исследовательский пробник Kalkan

Одноразовая утилита, чтобы **эмпирически** выяснить модель данных библиотеки
Kalkan (какие поля извлекаются, в каком формате, что нужно на входе) и на этом
спроектировать контракты сервиса. Это не часть продакшна, а инструмент
исследования; заодно — заготовка cgo-обёртки `internal/native` и самотеста (§8.3).

## Что делает

Через реальную нативную библиотеку: `KC_Init` → `LoadKeyStore` (PKCS12) →
экспорт сертификата → `X509CertificateGetInfo` по **всем** `KC_CERTPROP_*` →
round-trip `SignData`/`VerifyData` → `KC_GetTimeFromSig`. Печатает JSON-отчёт в
stdout, лог — в stderr.

## Запуск (BYOL — библиотека и ключи не в репозитории)

```
# NATIVE_DIR/lib/  должен содержать libkalkancryptwr-64.so и libkalkancrypto.so
# NATIVE_DIR/keys/ — тестовые .p12 (пароль в KEY_PASS, по умолчанию Qwerty12)
NATIVE_DIR=/path/to/native KEY_FILE=fiz.p12 ./run.sh
```

Требуется Docker (нативная либа — только Linux/amd64; на Apple Silicon идёт через
эмуляцию). Цепочка `LD_PRELOAD` и рантайм-зависимости зашиты в `Dockerfile`.

## Файлы

- `main.go` — драйвер (cgo), формирует JSON-отчёт.
- `shim.c` / `shim.h` — тонкие C-обёртки над таблицей `KC_GetFunctionList`.
- `iconv_compat.c` — шим GNU libiconv → glibc iconv.
- `KalkanCrypt.h` — заголовок API (из SDK).
- `Dockerfile`, `run.sh` — сборка и запуск в контейнере.
- **`FINDINGS.md`** — итоговые находки (форматы полей, различия профилей,
  роль-OID, зависимости среды). Главный результат для проектирования контрактов.
- `sample-report.json` — пример отчёта (тестовые данные).
