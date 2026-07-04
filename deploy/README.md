# Deployment

Starting-point artifacts for running `qoltanba`. Two deploy modes; both are
**BYOL** — you supply the Kalkan native library, it is never bundled.

| File | Purpose |
|------|---------|
| `Dockerfile` | glibc runtime image (binary only; native lib mounted at runtime) |
| `compose.yaml` | Docker Compose: builds the image, mounts `../native/` as the BYOL bundle |
| `config.example.yaml` | example config file (YAML; TOML/JSON also accepted) |
| `qoltanba.service` | systemd unit (`EnvironmentFile` + `LoadCredential` + `SIGHUP` reload) |
| `qoltanba.env` | non-secret env for the systemd unit |
| `../.env.example` | full env reference (all settings) |

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
