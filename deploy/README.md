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
