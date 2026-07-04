# Окружение для функциональных тестов драйвера против РЕАЛЬНОЙ библиотеки Kalkan.
# linux/amd64 — нативная либа существует только под эту платформу (на Apple
# Silicon идёт через эмуляцию: медленно, но работает). Платформа задаётся флагом
# `docker build --platform=linux/amd64` в run.sh, а не константой в FROM (иначе
# BuildKit ругается FromPlatformFlagConstDisallowed). Репозиторий и каталог
# native/ монтируются при запуске (BYOL — в образ не копируются).
FROM golang:1.25-bookworm

# Рантайм-зависимости libkalkancryptwr (см. .claude/docs/kalkan-api/loading.md).
# patchelf — на случай стратегии изоляции через soname-копии враппера.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcsclite1 libltdl7 zlib1g patchelf \
    && rm -rf /var/lib/apt/lists/*

# Шим совместимости GNU libiconv -> glibc iconv (символы libiconv_* в враппере).
COPY iconv_compat.c /opt/iconv_compat.c
RUN gcc -shared -fPIC -o /opt/iconv_compat.so /opt/iconv_compat.c

# Цепочка LD_PRELOAD (эмпирически выверена; libkalkancrypto — из монтируемого
# каталога native, путь фиксирован в run.sh как /src/native/linux-x64).
ENV LD_PRELOAD="/opt/iconv_compat.so /usr/lib/x86_64-linux-gnu/libm.so.6 /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 /src/native/linux-x64/libkalkancrypto.so"

# Кэш сборки Go внутри контейнера (ephemeral).
ENV GOCACHE=/tmp/gocache GOFLAGS=-mod=mod
WORKDIR /src
