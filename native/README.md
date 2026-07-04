# native/ — нативные библиотеки Kalkan и тестовый материал (BYOL, локально)

> **НЕ коммитить.** Библиотека Kalkan проприетарная (права у НУЦ РК / АО «НИТ»);
> тестовые `.p12` — секретный ключевой материал. Всё содержимое исключено из git
> (см. корневой `.gitignore`). Это **локальная** рабочая папка для разработки и
> e2e-тестов — воплощение принципа Bring-Your-Own-Library.

## Раскладка

```
native/
  include/KalkanCrypt.h              заголовок C-API (интерфейс)
  linux-x64/
    libkalkancryptwr-64.so           → симлинк на .2.0.13 (враппер C-API)
    libkalkancryptwr-64.so.2.0.13     реальный враппер v2.0.13
    libkalkancrypto.so                OpenSSL-1.1-форк — ОБЯЗАТЕЛЬНАЯ зависимость
  windows-x64/  KalkanCrypt.dll  libcrypto-x64.dll  libssl-x64.dll
  windows-x86/  KalkanCrypt.dll  libcrypto.dll      libssl.dll
  keys-and-certs/                    тестовые ключи всех профилей + CA + CRL
  changelog.txt                      история версий SDK (для матрицы совместимости)
```

## Зависимости при загрузке

**Linux** — путь к врапперу для `dlopen` / `--lib-path`:

```
native/linux-x64/libkalkancryptwr-64.so        # симлинк → …so.2.0.13
```

Враппер не грузится без `libkalkancrypto.so` (OpenSSL-1.1-форк; на голом OpenSSL 3
падает) + GNU libiconv/pcsclite/libm. Цепочка `LD_PRELOAD` (детали —
`.claude/docs/kalkan-api/loading.md`):

```
LD_PRELOAD="./iconv_compat.so /usr/lib/x86_64-linux-gnu/libm.so.6 \
            /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \
            native/linux-x64/libkalkancrypto.so"
```

**Windows** — `--lib-path` на `native/windows-x64/KalkanCrypt.dll` (или `windows-x86/`);
рядом должны лежать `libcrypto-*.dll` и `libssl-*.dll` той же разрядности (уже здесь).

## Тестовые ключи

`keys-and-certs/` — `.p12` НУЦ РК по профилям (физлицо, первый руководитель,
сотрудник, право подписи, инфосистема, казначейство), в вариантах `valid`/`revoked`,
два периода. Пароль контейнеров — **`Qwerty12`**. Плюс тестовые CA
(`CA_Test/…nca_gost2022_test.cer`, `…root_test_gost_2022.cer`) и CRL. Набор
`2026.05.08-2027.05.07` — тот, на котором сверялись эмпирические факты в доках.

## Версии

Взята **v2.0.13** (последняя, под неё выверены доки). В SDK также есть
**сертифицированная v2.0.2** — если для комплаенса в РК нужна именно она, взять из
`SDK.7z` (`C/Linux/C/libs/v2.0.2 (Сертифицированная версия)/`).
