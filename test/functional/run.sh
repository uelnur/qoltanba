#!/usr/bin/env bash
# Запуск функциональных тестов драйвера против реальной библиотеки Kalkan из
# native/. BYOL: либа и ключи монтируются, в образ не попадают.
#
#   test/functional/run.sh                      # пул размера 1 (общий dlopen)
#   QOLTANBA_POOL=4 QOLTANBA_ISO=1 test/functional/run.sh   # изолированный пул
#   test/functional/run.sh -run TestFunctional_SignVerifyCMS   # конкретный тест
#
# Требуется Docker с поддержкой linux/amd64 (на Apple Silicon — эмуляция).
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$(pwd)"

KEY="${QOLTANBA_KEY:-native/keys-and-certs/Gost2015/2026.05.08-2027.05.07/Физическое лицо/valid/GOST512_ec425659bd2fc6dc587b871aede1857727cf8451.p12}"
# Второй подписант (иной профиль) для теста мультиподписи.
KEY2="${QOLTANBA_KEY2:-native/keys-and-certs/Gost2015/2026.05.08-2027.05.07/Юридическое лицо/Первый руководитель/valid/GOST512_303eebdf17969f3edede9bd9828fb1355aabbe4e.p12}"
# Revoked counterpart of KEY (same CA) — for the CRL revocation check.
KEY_REVOKED="${QOLTANBA_KEY_REVOKED:-native/keys-and-certs/Gost2015/2026.05.08-2027.05.07/Физическое лицо/revoked/GOST512_bacea55cbcdf38c861fb3f341854c53ec9ed6ecd.p12}"
# CRL: bundled file (offline fallback) + live URL (own-fetch, network required).
CRL="${QOLTANBA_CRL:-native/keys-and-certs/CRL/nca_gost2022_test.crl}"
CRL_URL="${QOLTANBA_CRL_URL:-http://test.pki.gov.kz/crl/nca_gost2022_test.crl}"
OCSP_URL="${QOLTANBA_OCSP_URL:-http://test.pki.gov.kz/ocsp/}"
PASS="${QOLTANBA_PASS:-Qwerty12}"
POOL="${QOLTANBA_POOL:-1}"
ISO="${QOLTANBA_ISO:-0}"

if [[ ! -f "$REPO/native/linux-x64/libkalkancryptwr-64.so.2.0.13" ]]; then
	echo "нет нативной библиотеки в native/linux-x64 — положите её (BYOL)" >&2
	exit 1
fi

docker build --platform=linux/amd64 -t kalkan-functional "$REPO/test/functional"

# Тестовые аргументы после run.sh пробрасываются в go test (по умолчанию — все
# TestFunctional_*).
ARGS=("$@")
if [[ ${#ARGS[@]} -eq 0 ]]; then
	ARGS=(-run TestFunctional)
fi

docker run --rm --platform=linux/amd64 \
	-v "$REPO":/src -w /src \
	-e QOLTANBA_LIB=/src/native/linux-x64/libkalkancryptwr-64.so \
	-e QOLTANBA_DEP=/src/native/linux-x64/libkalkancrypto.so \
	-e QOLTANBA_KEY="/src/$KEY" \
	-e QOLTANBA_KEY2="/src/$KEY2" \
	-e QOLTANBA_KEY_REVOKED="/src/$KEY_REVOKED" \
	-e QOLTANBA_CRL="/src/$CRL" \
	-e QOLTANBA_CRL_URL="$CRL_URL" \
	-e QOLTANBA_OCSP_URL="$OCSP_URL" \
	-e QOLTANBA_PASS="$PASS" \
	${QOLTANBA_HASH_ALG:+-e QOLTANBA_HASH_ALG="$QOLTANBA_HASH_ALG"} \
	${QOLTANBA_DUMP_CERT:+-e QOLTANBA_DUMP_CERT="$QOLTANBA_DUMP_CERT"} \
	-e QOLTANBA_POOL="$POOL" \
	-e QOLTANBA_ISO="$ISO" \
	-e QOLTANBA_CA_ROOT=/src/native/keys-and-certs/CA_Test/ROOT/root_test_gost_2022.cer \
	-e QOLTANBA_CA_NCA=/src/native/keys-and-certs/CA_Test/NCA/nca_gost2022_test.cer \
	kalkan-functional \
	go test -tags qoltanba_functional -count=1 -v ./internal/native/ ./test/e2e/ "${ARGS[@]}"
