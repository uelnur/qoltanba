#!/usr/bin/env bash
# Register a self-hosted GitHub Actions runner on THIS machine for the Kalkan
# functional workflow (.github/workflows/functional.yml, label: kalkan).
#
# Why self-hosted: functional tests run against the REAL proprietary Kalkan
# library (BYOL) which cannot live on GitHub-hosted runners. This host already
# has native/ + Docker, so it is the natural place to run them.
#
# The runner installs OUTSIDE the repo ($HOME by default) so it never pollutes
# the working tree. BYOL native/ stays where it is; the workflow copies it in
# per-job via the QOLTANBA_NATIVE_SRC repo variable.
#
# Prerequisites:
#   1. The repo must exist on GitHub and be pushed (Actions files must be there).
#   2. A runner registration token — get it at:
#        <repo> → Settings → Actions → Runners → New self-hosted runner
#      (it is short-lived; generate it just before running this).
#   3. Docker Desktop running (run.sh uses linux/amd64 via emulation).
#
# Usage:
#   REPO_URL=https://github.com/OWNER/REPO \
#   RUNNER_TOKEN=AXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
#   test/functional/setup-runner.sh
#
# Then start it:
#   (cd "$RUNNER_DIR" && ./run.sh)                       # foreground
#   (cd "$RUNNER_DIR" && ./svc.sh install && ./svc.sh start)  # launchd service
set -euo pipefail

REPO_URL="${REPO_URL:?set REPO_URL=https://github.com/OWNER/REPO}"
RUNNER_TOKEN="${RUNNER_TOKEN:?get a token: <repo> → Settings → Actions → Runners → New self-hosted runner}"
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner-kalkan}"
RUNNER_LABELS="${RUNNER_LABELS:-kalkan}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname -s)-kalkan}"

# Runner CPU arch for the macOS package.
case "$(uname -m)" in
	arm64) ARCH=arm64 ;;
	x86_64) ARCH=x64 ;;
	*) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

# Latest runner version (self-updates once connected, so this only needs to be
# recent enough to register). Falls back to a pinned version if the API is
# unreachable.
VERSION="${RUNNER_VERSION:-}"
if [[ -z "$VERSION" ]]; then
	VERSION="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
		| sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
fi
VERSION="${VERSION:-2.328.0}"

PKG="actions-runner-osx-${ARCH}-${VERSION}.tar.gz"
URL="https://github.com/actions/runner/releases/download/v${VERSION}/${PKG}"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"
if [[ ! -x ./config.sh ]]; then
	echo "downloading runner ${VERSION} (${ARCH})…"
	curl -fsSLo "$PKG" "$URL"
	tar xzf "$PKG"
	rm -f "$PKG"
fi

# --replace re-registers cleanly if a runner with this name already exists.
./config.sh \
	--url "$REPO_URL" \
	--token "$RUNNER_TOKEN" \
	--name "$RUNNER_NAME" \
	--labels "$RUNNER_LABELS" \
	--unattended \
	--replace

cat <<EOF

Runner "${RUNNER_NAME}" registered with label(s): ${RUNNER_LABELS}
Install dir: ${RUNNER_DIR}

Start it:
  foreground:  (cd "${RUNNER_DIR}" && ./run.sh)
  as service:  (cd "${RUNNER_DIR}" && ./svc.sh install && ./svc.sh start)

Then, once per repo, set the BYOL path the workflow provisions from:
  <repo> → Settings → Secrets and variables → Actions → Variables →
    QOLTANBA_NATIVE_SRC = $(cd "$(dirname "$0")/../.." && pwd)/native

Trigger the functional run:
  <repo> → Actions → "Functional (real Kalkan)" → Run workflow
EOF
