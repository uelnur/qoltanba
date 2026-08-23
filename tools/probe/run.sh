#!/usr/bin/env bash
# Сборка и запуск пробника против нативной библиотеки Kalkan и тестового ключа.
#
# BYOL: библиотека и ключи не входят в репозиторий — путь к каталогу с ними
# задаётся переменной NATIVE_DIR (структура: lib/, keys/, ca/).
#
#   NATIVE_DIR=/path/to/native ./run.sh
#
# Ожидается:
#   $NATIVE_DIR/lib/libkalkancryptwr-64.so
#   $NATIVE_DIR/keys/individual_valid.p12   (пароль в KEY_PASS, по умолчанию Qwerty12)
set -euo pipefail

NATIVE_DIR="${NATIVE_DIR:?укажите NATIVE_DIR — каталог с lib/ keys/ ca/}"
KEY_FILE="${KEY_FILE:-individual_valid.p12}"
KEY_PASS="${KEY_PASS:-Qwerty12}"
LIB_FILE="${LIB_FILE:-libkalkancryptwr-64.so}"
# Необязательный второй подписант для теста множественной подписи:
KEY2_FILE="${KEY2_FILE:-}"   # напр. ur_ruk.p12
KEY2_PASS="${KEY2_PASS:-Qwerty12}"

cd "$(dirname "$0")"

docker build --platform=linux/amd64 -t kalkan-probe .

docker run --rm --platform=linux/amd64 \
    -v "$NATIVE_DIR/lib:/native/lib:ro" \
    -v "$NATIVE_DIR/keys:/native/keys:ro" \
    -v "$NATIVE_DIR/ca:/native/ca:ro" \
    -e LIB_PATH="/native/lib/$LIB_FILE" \
    -e KEY_PATH="/native/keys/$KEY_FILE" \
    -e KEY_PASS="$KEY_PASS" \
    -e CA_DIR="/native/ca" \
    ${KEY2_FILE:+-e KEY2_PATH="/native/keys/$KEY2_FILE" -e KEY2_PASS="$KEY2_PASS"} \
    kalkan-probe "$@"
