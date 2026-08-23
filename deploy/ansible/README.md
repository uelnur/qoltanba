# Ansible role — qoltanba on a VM

Installs qoltanba from the `.deb`/`.rpm` package (see `deploy/nfpm.yaml`), wires the
environment file and optional config, and manages the systemd unit. The Kalkan
library stays **Bring-Your-Own** — pre-stage it on the host or push it via
`qoltanba_lib_src`.

## What it does

1. Installs the package from `qoltanba_deb_url` or a local `qoltanba_deb_path`
   (`apt` on Debian/Ubuntu, `dnf` on RHEL family).
2. Ensures the BYOL library directory exists and (optionally) pushes the library;
   fails fast if the library is missing.
3. Templates `/etc/qoltanba/qoltanba.env` and, when provided, `/etc/qoltanba/config.yaml`.
4. Enables and starts the `qoltanba` systemd service, restarting on any change.

The package's unit runs under `DynamicUser=yes` with `ProtectSystem=strict` and
`ReadOnlyPaths=/opt/kalkan /etc/qoltanba`, so the role creates no user and touches
only the config dir and the library path.

## Usage

```yaml
- hosts: qoltanba
  become: true
  roles:
    - role: qoltanba
      vars:
        qoltanba_deb_url: "https://.../qoltanba_1.4.0_amd64.deb"
        qoltanba_lib_src: "./secret/libkalkancryptwr-64.so"   # BYOL
        qoltanba_env:
          QOLTANBA_HTTP_ADDR: ":8080"
          QOLTANBA_TRUST_USE_RK_REGISTRY: "true"
```

See `defaults/main.yml` for all variables and `playbook.yml` for a full example.

## Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `qoltanba_deb_url` / `qoltanba_deb_path` | `""` | Package source (set one). |
| `qoltanba_lib_dir` / `qoltanba_lib_file` | `/opt/kalkan` / `libkalkancryptwr-64.so` | BYOL library location the service is pointed at. |
| `qoltanba_lib_src` | `""` | Optional local library file to push to the host. |
| `qoltanba_env` | see defaults | Environment file contents (non-secret). |
| `qoltanba_config_yaml` | `{}` | Optional structured config → `/etc/qoltanba/config.yaml`. |
| `qoltanba_service_enabled` / `qoltanba_service_state` | `true` / `started` | systemd management. |

## Secrets & observability

- **Secrets** (keystore passwords/PINs) go through systemd credentials, not the env
  file — see the unit's `LoadCredential` + `QOLTANBA_<KEY>_FILE` convention.
- **Metrics** are on the work port (`/metrics`, default `:8080`). Point Prometheus at
  it with `deploy/observability/prometheus/scrape.example.yaml` and load
  `deploy/observability/prometheus/alerts.yaml` as a `rule_files` entry.
