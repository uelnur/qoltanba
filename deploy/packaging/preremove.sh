#!/bin/sh
# Pre-remove: stop and disable the unit if it is active.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop qoltanba >/dev/null 2>&1 || true
	systemctl disable qoltanba >/dev/null 2>&1 || true
fi
