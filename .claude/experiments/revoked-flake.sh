#!/usr/bin/env bash
# Decisive experiment for the Kalkan revoked-OCSP double-free (see
# .claude/docs/kalkan-native-flake.md). Question: does a REAL revoked cert
# validated against PROD OCSP trigger the crash (=> prod at risk on revocation),
# or only the TEST revoked cert/responder?
#
# Config already validated as a reproducer: full e2e suite + test-revoked = 6/80;
# same suite -revoked = 0/80. Here we swap in the REAL revoked cert.
#
# PREREQS:
#   * Real VALID key at native/valid/ (VALID_REAL_REL) with password in native/pwd.txt.
#   * Real REVOKED .p12 in native/ — set REVOKED_REAL below (path relative to repo root).
#     It MUST be genuinely revoked in prod so ocsp.pki.gov.kz returns "revoked".
#   * If the revoked key's password differs from the valid key's: the e2e harness uses a
#     single QOLTANBA_PASS, so both must share it. If they can't, add a REVOKED_PASS shim
#     to test/e2e/common_test.go keyFromEnv (2 lines) — ask the maintainer.
#   * Docker with linux/amd64 + the kalkan-functional image (built by test/functional/run.sh).
#
# RUN:  bash .claude/experiments/revoked-flake.sh
#       NCTRL=40 NREAL=120 bash .claude/experiments/revoked-flake.sh   # tune iters
#
# READ RESULT: RESULT REALREVOKED line + any "NATIVE CRASH" lines.
#   * >=1 crash on REALREVOKED  -> prod IS at risk on revocation checks (conclusive).
#   * 0 crashes on REALREVOKED  -> test revoked material specifically is the culprit
#     (p~0.0001 vs the 7.5% control) -> prod likely safe; update the doc accordingly.
set -uo pipefail
cd "$(dirname "$0")/../.." ; REPO="$(pwd)"

# ---- FILL IN -------------------------------------------------------------------
REVOKED_REAL_REL="native/GOST512_8004d6600b7a543bc144835b5faa00837df4a685.p12"   # real cert, revoked 2026-08 (prod OCSP: revoked, reason "superseded")
# --------------------------------------------------------------------------------

VALID_REAL_REL="native/valid/GOST512_c0110e34a042d6eb99a452a58af7622d3b6baa69.p12"
KDIR="native/keys-and-certs/Gost2015/2026.05.08-2027.05.07"
OUTDIR="$REPO/native/.flake-logs"        # gitignored (native/ is ignored); durable across sessions
NCTRL="${NCTRL:-40}"
NREAL="${NREAL:-120}"

[ -f "$REPO/$REVOKED_REAL_REL" ] || { echo "!! set REVOKED_REAL_REL to your revoked .p12 (not found: $REVOKED_REAL_REL)"; exit 2; }
[ -f "$REPO/native/pwd.txt" ]    || { echo "!! native/pwd.txt (valid-key password) missing"; exit 2; }
PW="$(cat "$REPO/native/pwd.txt")"
REVOKED_PASS="${REVOKED_PASS:-$PW}"      # override if the revoked key has a different password
mkdir -p "$OUTDIR"

# Prod trust anchors (NUC intermediate + KUC root) — fetch once, cache in OUTDIR.
[ -s "$OUTDIR/nca_gost_2022.cer" ]      || curl -fsS -o "$OUTDIR/nca_gost_2022.cer"      "http://pki.gov.kz/cert/nca_gost_2022.cer"
[ -s "$OUTDIR/root_gost2015_2022.cer" ] || curl -fsS -o "$OUTDIR/root_gost2015_2022.cer" "https://root.gov.kz/cert/root_gost2015_2022.cer"

docker run --rm --platform=linux/amd64 -v "$REPO":/src -w /src -v "$OUTDIR":/out \
  -e MALLOC_CHECK_=3 -e MALLOC_PERTURB_=165 -e "GLIBC_TUNABLES=glibc.malloc.check=3" \
  -e NCTRL="$NCTRL" -e NREAL="$NREAL" -e RPASS="$REVOKED_PASS" \
  -e QOLTANBA_LIB=/src/native/linux-x64/libkalkancryptwr-64.so -e QOLTANBA_DEP=/src/native/linux-x64/libkalkancrypto.so \
  kalkan-functional bash -c '
    go test -tags qoltanba_functional -c -o /tmp/e2e.test ./test/e2e/ 2>&1 | tail -1
    T="/src/'"$KDIR"'"
    run_loop() { local name="$1" n="$2"; shift 2; local crash=0 hang=0 other=0
      for i in $(seq 1 "$n"); do
        timeout 150 env "$@" /tmp/e2e.test -test.run TestFunctional -test.count=1 >/out/rx_${name}.log 2>&1; rc=$?
        if grep -qE "double free|SIGABRT|SIGSEGV|corrupt|invalid pointer" /out/rx_${name}.log; then crash=$((crash+1)); cp /out/rx_${name}.log /out/rx_${name}_crash_${crash}.log; echo "  [$name] iter $i: NATIVE CRASH (#$crash)";
        elif [ $rc -eq 124 ]; then hang=$((hang+1)); elif [ $rc -ne 0 ]; then other=$((other+1)); fi
        [ $((i % 20)) -eq 0 ] && echo "  [$name] $i/$n (crash=$crash hang=$hang)"
      done
      echo "RESULT $name: NATIVE_CRASH=$crash HANG=$hang OTHER=$other / $n"; }
    echo ">>> CONTROL: TEST valid + TEST revoked (expect a few crashes = reproducer live), x$NCTRL"
    run_loop CTRL "$NCTRL" \
      QOLTANBA_KEY="$T/Физическое лицо/valid/GOST512_ec425659bd2fc6dc587b871aede1857727cf8451.p12" \
      QOLTANBA_KEY2="$T/Юридическое лицо/Первый руководитель/valid/GOST512_303eebdf17969f3edede9bd9828fb1355aabbe4e.p12" \
      QOLTANBA_KEY_REVOKED="$T/Физическое лицо/revoked/GOST512_bacea55cbcdf38c861fb3f341854c53ec9ed6ecd.p12" \
      QOLTANBA_PASS=Qwerty12 \
      QOLTANBA_CA_ROOT=/src/native/keys-and-certs/CA_Test/ROOT/root_test_gost_2022.cer \
      QOLTANBA_CA_NCA=/src/native/keys-and-certs/CA_Test/NCA/nca_gost2022_test.cer \
      QOLTANBA_OCSP_URL=http://test.pki.gov.kz/ocsp/ QOLTANBA_TSA_URL=http://test.pki.gov.kz/tsp/
    echo ">>> DECISIVE: REAL valid + REAL revoked + PROD OCSP, x$NREAL"
    run_loop REALREVOKED "$NREAL" \
      QOLTANBA_KEY="/src/'"$VALID_REAL_REL"'" QOLTANBA_KEY2="/src/'"$VALID_REAL_REL"'" \
      QOLTANBA_KEY_REVOKED="/src/'"$REVOKED_REAL_REL"'" QOLTANBA_PASS="$RPASS" \
      QOLTANBA_CA_ROOT=/out/root_gost2015_2022.cer QOLTANBA_CA_NCA=/out/nca_gost_2022.cer \
      QOLTANBA_OCSP_URL=http://ocsp.pki.gov.kz QOLTANBA_TSA_URL=http://tsp.pki.gov.kz
    echo ">>> DONE"
  ' 2>&1 | tee "$OUTDIR/run_$(date +%Y%m%d_%H%M%S 2>/dev/null || echo now).log"
