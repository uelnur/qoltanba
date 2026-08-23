# Пробник собирается и запускается в linux/amd64 (нативная либа Kalkan — только
# под эту платформу). На Apple Silicon идёт через эмуляцию — медленно, но работает.
# Платформа задаётся флагом `docker build --platform=linux/amd64` в run.sh, а не
# константой в FROM (иначе BuildKit ругается FromPlatformFlagConstDisallowed).
FROM golang:1.25-bookworm

# Возможные рантайм-зависимости libkalkancryptwr (уточняются по `readelf -d`).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcsclite1 libltdl7 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
# Шим совместимости GNU libiconv -> glibc iconv (см. iconv_compat.c).
RUN gcc -shared -fPIC -o /opt/iconv_compat.so iconv_compat.c
RUN CGO_ENABLED=1 go build -o /usr/local/bin/probe .

# Цепочка LD_PRELOAD, выясненная эмпирически (см. FINDINGS.md):
#  - iconv_compat.so   : GNU libiconv -> glibc iconv
#  - libm / libpcsclite : символы, не указанные в NEEDED враппера
#  - libkalkancrypto.so : OpenSSL-1.1-форк Kalkan (даёт SRP_* и прочие символы;
#    в OpenSSL 3.x они удалены). Монтируется в /native/lib вместе с враппером.
ENV LD_PRELOAD="/opt/iconv_compat.so /usr/lib/x86_64-linux-gnu/libm.so.6 /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 /native/lib/libkalkancrypto.so"

# Библиотеки Kalkan и ключи НЕ копируются в образ (BYOL) — монтируются при запуске
# (нужны и libkalkancryptwr-64.so, и libkalkancrypto.so в /native/lib).
ENTRYPOINT ["/usr/local/bin/probe"]
