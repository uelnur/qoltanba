# Deployment

Starting-point artifacts for running `qoltanba`. Two deploy modes; both are
**BYOL** — you supply the Kalkan native library, it is never bundled.

| File | Purpose |
|------|---------|
| `Dockerfile` | glibc runtime image (binary only; native lib mounted at runtime) |
| `compose.yaml` | Docker Compose: builds the image, mounts `../native/` as the BYOL bundle |
| `config.example.yaml` | example config file (YAML; TOML/JSON also accepted) |
| `qoltanba.service` | systemd unit for a **manual** install (`/usr/local/bin`) |
| `qoltanba.env` | non-secret env for the systemd unit |
| `nfpm.yaml` + `packaging/` | build `.deb`/`.rpm` (native packages, systemd auto-registration) |
| `helm/qoltanba/` | Helm chart for Kubernetes |
| `observability/` | ready-to-use Grafana dashboard + Prometheus alert rules + scrape config |
| `terraform/` | Terraform module wrapping the Helm release (Kubernetes) |
| `ansible/` | Ansible role installing the `.deb`/`.rpm` + systemd (VM) |
| `postman/` | Postman collection + environment |
| `../api/openapi.yaml` | OpenAPI 3.1 spec for the REST API |
| `../.env.example` | full env reference (all settings) |

**Native binary is the primary path** (many servers run without containers); Docker,
Helm and packages are conveniences on top.

## Configuration model

One registry entry per setting yields three surfaces — flag `--log-level`, env
`QOLTANBA_LOG_LEVEL`, file key `log.level`. Precedence, low → high:

```
defaults  <  config file  <  environment  <  command-line flags
```

Secrets are read only from the environment or a `QOLTANBA_<KEY>_FILE` side-file
(Docker/K8s secrets, systemd `LoadCredential`), never from flags. Inspect the
effective config, with origins and secrets masked:

```
qoltanba config-dump
qoltanba config-check   # fail-fast validation (CI/CD)
```

## Crypto runs in child processes

The service re-executes its own binary (`qoltanba crypto-worker`) and runs every
cryptographic operation there, keeping the Kalkan library out of the service
process entirely. The library leaks native memory on every call (~1 MB per CMS
verification) and corrupts its global state when it parses a revoked OCSP
verdict; neither can be undone in-process, so children are recycled on an
operation and memory budget and respawned after a crash. Plan for it when sizing
and confining the service:

- One process per `QOLTANBA_CRYPTO_WORKER_PROCESSES` (default: the worker count)
  plus `QOLTANBA_CRYPTO_WORKER_STANDBY` pre-warmed spares (default 1), each
  loading its own copy of the library. Budget memory as
  `service (~20 MB) + processes × QOLTANBA_CRYPTO_WORKER_MAX_RSS_MB` (default
  512 MiB) `+ standby × ~25 MB`, and count all of them in `TasksMax`/pid limits.
- The spares exist because recycling is routine: they take over instantly instead
  of making a request wait for a library load (measured: ~86 ms per recycle).
  Set `QOLTANBA_CRYPTO_WORKER_STANDBY=0` to trade that latency back for memory.
- The child inherits the environment, so `LD_LIBRARY_PATH`/`LD_PRELOAD` and the
  library path reach it unchanged; nothing else is passed to it.
- `qoltanba_crypto_worker_total{event="recycle"}` is routine — that is the leak
  being discarded. `event="crash"` rising means the library defect is being hit
  in production: the service survives it (the call is retried), but it is worth
  an alert.
- Lowering `MAX_RSS_MB` or `MAX_OPS` trades a more frequent library reload
  (hundreds of ms, paid by the first call after a recycle) for a lower memory
  ceiling.
- Set `QOLTANBA_CRYPTO_WORKER_ENABLED=false` only if your environment forbids
  spawning processes; the service then loads the library itself and will grow
  until it is killed, and can abort on a revocation check.

## Signing artifacts in CI/CD

The CLI transport is a pipeline step: JSON on stdin, JSON on stdout, exit code as
the gate. `-fail-invalid` makes a negative verification exit 2, which is what
turns a check into a gate — by default an invalid signature is a successful
answer, not an error.

```
# sign a release artifact
jq -nc --arg data "$(base64 -w0 < app.tar.gz)" --arg p12 "$KEY_B64" --arg pass "$KEY_PASS" \
  '{format:"cms", data:$data, detached:true, outputPem:true, key:{p12:$p12, password:$pass}}' \
  | qoltanba sign -keys-allow-inline | jq -r .signature | base64 -d > app.tar.gz.p7s

# gate: fail the build unless the artifact verifies
jq -nc --arg sig "$(base64 -w0 < app.tar.gz.p7s)" --arg data "$(base64 -w0 < app.tar.gz)" \
  '{format:"cms", signature:$sig, data:$data, detached:true, inputPem:true, report:true}' \
  | qoltanba verify -fail-invalid
```

Exit codes: `0` verified, `2` completed but negative, `1`/`3+` the check could not
run (see the JSON error envelope). Keys go **inline on stdin**, never as a command
argument or a file on the runner — arguments are visible to every process on the
host.

A ready composite action lives at `.github/actions/qoltanba` (`uses:
uelnur/qoltanba/.github/actions/qoltanba@<tag>`), taking `op`, `file`, `key`,
`key-password` and `lib-path`. The Kalkan library stays bring-your-own: point
`lib-path` at a copy the runner already has (self-hosted runner, private
artifact, internal image) — it is proprietary and is not distributed here.

## Docker

```
docker compose -f deploy/compose.yaml up --build
```

The image is glibc/amd64 (Kalkan is dlopen'd into the process; musl/static would
crash it). Mount your Kalkan library and its runtime deps (OpenSSL-1.1 fork,
iconv) — the compose file maps `../native/linux-x64` to `/opt/kalkan`. Loader
wiring (`LD_LIBRARY_PATH`/`LD_PRELOAD`) mirrors `test/functional/`; adjust to your
bundle.

## systemd (native binary)

Build a glibc binary (`CGO_ENABLED=1 go build ./cmd/qoltanba`), then follow
the install steps in `qoltanba.service`. Logs go to journald (stdout/stderr,
12-factor). `systemctl reload` re-reads the cheap subgroup (log level, telemetry);
library/pool changes need a restart.

## Transports

This build ships **CLI**, **REST** and **gRPC**. Serve REST with `-http` and/or
gRPC with `-grpc` (both can run together on one service instance). Run a one-shot
CLI op by piping a JSON request:

```
echo '{"format":"cms","signature":"<base64>"}' | qoltanba verify
```

The gRPC contract is `api/qoltanba/v1/service.proto` (generate clients for
JS/TS, Java, Python, PHP, C# from it). Default address `:9091`.

## Native packages (.deb / .rpm)

For servers without Docker. The **Release workflow builds them automatically** on a
`vX.Y.Z` tag (via [nfpm](https://nfpm.goreleaser.com), no native tooling). The
package installs the binary to `/usr/bin/qoltanba`, the systemd unit to
`/lib/systemd/system/`, config to `/etc/qoltanba/` (the `.env` is a conffile —
preserved on upgrade), and the OpenAPI spec to `/usr/share/qoltanba/`. It does
**not** enable the service — first supply the BYOL library and config:

```
sudo apt install ./qoltanba_*.deb        # or: sudo rpm -i qoltanba-*.rpm
sudoedit /etc/qoltanba/qoltanba.env      # set QOLTANBA_LIB_PATH
sudo cp /etc/qoltanba/config.example.yaml /etc/qoltanba/config.yaml
qoltanba config-check
sudo systemctl enable --now qoltanba
```

Build locally: `VERSION=1.2.3 ARCH=amd64 nfpm pkg --config deploy/nfpm.yaml --packager deb --target dist/`.

## Kubernetes (Helm)

Chart in `deploy/helm/qoltanba`. BYOL: you **must** point `byol.volume` at a source
that holds `libkalkancryptwr-64.so` and its runtime deps — the default is an empty
placeholder and readiness will not pass until you set it.

```
helm install qoltanba deploy/helm/qoltanba \
  --set image.repository=<your-registry>/qoltanba --set image.tag=<ver> \
  --set byol.volume.hostPath.path=/opt/kalkan --set byol.volume.hostPath.type=Directory
```

Non-secret settings go under `config` (→ ConfigMap → env), secrets under
`secretConfig` (→ Secret) or an existing Secret via `extraEnvFrom`. `/metrics` is
served on the HTTP work port; the Service is annotated for Prometheus scraping.

Prometheus Operator + Grafana users can turn on the shipped assets:
`--set metrics.serviceMonitor=true,metrics.prometheusRule=true,metrics.dashboardConfigMap=true`.

## Terraform & Ansible

- **Terraform** (`terraform/`): a module wrapping the Helm release for Kubernetes —
  manage qoltanba as Terraform state, with the common values (image, BYOL volume,
  config, metrics toggles) as typed inputs. See `terraform/README.md`.
- **Ansible** (`ansible/`): a role installing the `.deb`/`.rpm`, wiring the env/config
  and managing the systemd unit on a VM (BYOL-aware). See `ansible/README.md`.

## Observability (Grafana / Prometheus)

`observability/` ships a Grafana dashboard, Prometheus alert rules and a scrape
example — all built on the metrics the service actually exports (`internal/metrics`).
Import and go; details and the metrics vocabulary are in `observability/README.md`.
The Helm chart can render the ServiceMonitor/PrometheusRule/dashboard ConfigMap
(gated in `values.yaml`); `make sync-observability` keeps the chart's copies in step
with the canonical files. The dev playground brings the whole stack (Prometheus +
Grafana + Loki + Promtail) up against a live service.

## API spec & Postman (try-it-now)

**Both are generated from the Go types** (`tools/openapigen`) — the component
schemas are reflected from `internal/transport/dto` (requests) and `internal/core`
(responses), so they never drift from the code. Do not hand-edit them; run
`make openapi` and commit. CI (`make check-generated`) fails a PR whose code
changed a request/response shape without regenerating, then lints the spec
(`make openapi-lint`, Redocly). Run `make hooks` once per clone to enable the git hooks (`.githooks/`):
**pre-commit** applies `gofmt` and blocks on OpenAPI/Postman drift (fast);
**pre-push** runs the full gate `make check` (build, vet, lint, tests). Both catch
issues locally before CI; bypass with `--no-verify` in a pinch.

- **OpenAPI 3.1:** `api/openapi.yaml` — import into Swagger UI / Redoc, or generate
  clients. All request and response keys are lowerCamelCase.
- **Postman:** import `deploy/postman/qoltanba.postman_collection.json` and the
  `…_environment.json`; set `baseUrl` and the base64/secret variables.

Quick smoke against a running REST instance:

```
curl -s localhost:8080/readyz
curl -s localhost:8080/statusz | jq .
echo '{"format":"cms","signature":"<base64>","checkCertTime":true}' \
  | curl -s -XPOST localhost:8080/verify -H 'Content-Type: application/json' -d @-
```
