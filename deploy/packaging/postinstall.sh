#!/bin/sh
# Post-install: register the unit. We do NOT enable/start it — the service needs
# a BYOL Kalkan library (QOLTANBA_LIB_PATH) and a config first.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'
qoltanba installed.

Next steps:
  1. Provide the Kalkan library (BYOL) and set QOLTANBA_LIB_PATH in
     /etc/qoltanba/qoltanba.env (default /opt/kalkan/libkalkancryptwr-64.so).
  2. Create /etc/qoltanba/config.yaml (see /etc/qoltanba/config.example.yaml).
  3. Validate:  qoltanba config-check
  4. Enable:    systemctl enable --now qoltanba

OpenAPI spec: /usr/share/qoltanba/openapi.yaml
EOF
