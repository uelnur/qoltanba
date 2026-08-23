# Загрузка библиотеки, среда, жизненный цикл

Часть справочника `kalkan-api` — сначала [`index.md`](index.md).
Как поднять либу до первого вызова метода.

## Платформы

Нативная либа существует только под **Linux x64** (`libkalkancryptwr-64.so`) и
**Windows x64/x86** (`KalkanCrypt.dll`). macOS/мобильных сборок в SDK нет — на
macOS работать через Linux-контейнер (`--platform=linux/amd64`; на Apple Silicon —
через эмуляцию, медленно, но работает).

## dlopen + таблица функций

```c
#include <dlfcn.h>
#include "KalkanCrypt.h"

static stKCFunctionsType *kc = NULL;   // таблица; хранить на всё время жизни

unsigned long kc_load(const char *libpath) {
    void *h = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);   // GLOBAL обязателен
    if (!h) return 1;                                    // dlerror() — текст
    int (*getlist)(stKCFunctionsType **) = dlsym(h, "KC_GetFunctionList");
    if (!getlist) return 2;
    int rv = getlist(&kc);
    return (rv != 0 || !kc) ? 3 : 0;                     // 0 → готово
}
// дальше зовёшь методы через таблицу: kc->KC_Init(); kc->SignData(...); …
```

Из cgo это оборачивают тонкими C-функциями (по одной на метод таблицы), чтобы Go
не работал с указателями внутри структуры напрямую, напр.:

```c
unsigned long kc_sign_data(const char *alias, int flags, char *in, int inlen,
                           unsigned char *out, int *outlen) {
    return kc->SignData((char*)alias, flags, in, inlen, NULL, 0, out, outlen);
}
```
    
- **`RTLD_GLOBAL` обязателен** — символы либы должны быть видны зависимым модулям
  (крипто-движку), иначе резолвинг падает.
- `KC_GetFunctionList` — **единственный** символ, который резолвишь по имени; всё
  остальное зовётся через `kc->…`.
- Windows-аналог: `LoadLibrary` + `GetProcAddress("KC_GetFunctionList")`.

## Зависимости среды (иначе dlopen падает)

`libkalkancryptwr-64.so` не самодостаточна — ей нужны символы, которых нет в её
`NEEDED`:

| Нужно | Откуда | Почему |
|-------|--------|--------|
| символы `SRP_*` и др. OpenSSL | **`libkalkancrypto.so`** — OpenSSL-**1.1**-форк Kalkan (из комплекта) | в системном OpenSSL 3.x эти символы удалены → на голом 3.x загрузка падает |
| `libiconv`, `libiconv_open`, `libiconv_close` | **GNU libiconv** | либа собрана против GNU libiconv; в glibc функции зовутся `iconv*` → нужен шим-алиас |
| `g_rgSCardT0Pci` | `libpcsclite.so.1` (`libpcsclite1`) | PC/SC (токены/смарт-карты) |
| `floor` | `libm.so.6` | libm |
| `libltdl.so.7`, `libz.so.1` | `libltdl7`, `zlib1g` | из `NEEDED` враппера |

**Шим iconv** (glibc-среда) — тонкие GNU-обёртки над glibc `iconv*`, собрать в `.so`
(`gcc -shared -fPIC -o iconv_compat.so iconv_compat.c`) и подложить через `LD_PRELOAD`:

```c
iconv_t libiconv_open(const char *to, const char *from){ return iconv_open(to,from); }
size_t  libiconv(iconv_t cd, char **in, size_t *inl, char **out, size_t *outl){ return iconv(cd,in,inl,out,outl); }
int     libiconv_close(iconv_t cd){ return iconv_close(cd); }
```

**Рабочая цепочка предзагрузки** (проверена на glibc/Debian-контейнере). Пути —
под локальную раскладку `native/` (см. `native/README.md`); либа-враппер грузится
из того же каталога:

```
# путь к врапперу для dlopen / --lib-path:
#   native/linux-x64/libkalkancryptwr-64.so   (симлинк → …so.2.0.13)
LD_PRELOAD="./iconv_compat.so /usr/lib/x86_64-linux-gnu/libm.so.6 \
            /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \
            native/linux-x64/libkalkancrypto.so"
```

Пакеты рантайма (Debian): `libpcsclite1 libltdl7 zlib1g`. Проверять реальные
зависимости конкретного файла — `readelf -d native/linux-x64/libkalkancryptwr-64.so`.

## Жизненный цикл

1. `kc->KC_Init()` — однократно после загрузки. `rc==0` → готово.
2. (опц.) `kc->KC_InitDebug()` — включить отладочный вывод либы (метод в **хвосте**
   таблицы — есть не во всех версиях).
3. Операции (любые методы таблицы).
4. Завершение: `kc->KC_XMLFinalize(); kc->KC_Finalize();` — оба, в этом порядке.

## ABI: таблица растёт между версиями

`stKCFunctionsType` **дополнялась** новыми указателями в конце (напр. `UVerifyData`,
`ZipConSign`/`ZipConVerify`/`KC_getCertFromZipFile`, `KC_InitDebug`). Старая либа
вернёт таблицу **короче** — чтение «хвостовых» указателей за её концом
небезопасно (мусор/креш). Практика:

- Фиксируй **минимальную поддерживаемую версию**; строй **карту возможностей**
  (какие методы реально доступны) и отключай недоступные операции.
- **Функции версии в API нет.** Источники по приоритету: конфиг → имя файла
  (`...so.2.0.13`) → эвристика по наличию хвостовых методов.

Ошибки загрузки диагностировать по этапам: нет файла / несовпадение разрядности /
нет символа `KC_GetFunctionList` / `KC_GetFunctionList` вернул `rv!=0` / отсутствует
зависимость среды. Коды методов после загрузки — [`reference.md`](reference.md).
