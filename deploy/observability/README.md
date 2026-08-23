# Observability assets

Ready-to-use Grafana dashboard, Prometheus alerting rules and scrape config for a
qoltanba deployment. Every panel and rule is built on a metric the service actually
exports (`internal/metrics`) — import and go, no editing required.

## Contents

| File | What |
|------|------|
| `grafana/dashboards/qoltanba-overview.json` | Overview dashboard: golden signals (rate/errors/latency/up), per-op latency, Kalkan pool, trust anchors, CRL cache, sessions, runtime. |
| `prometheus/alerts.yaml` | Alerting rules (availability, error ratio, latency, pool saturation, trust store, CRL freshness, revocation-error proxy). |
| `prometheus/scrape.example.yaml` | Static scrape config example for non-Kubernetes setups. |

## Metrics vocabulary

| Metric | Type | Labels |
|--------|------|--------|
| `qoltanba_requests_total` | counter | `transport`, `op`, `outcome` (`ok`/`client_error`/`server_error`, or the gRPC code name) |
| `qoltanba_request_duration_seconds` | histogram | `transport`, `op` |
| `qoltanba_pool_workers` | gauge | `state` (`busy`/`idle`) — present only when a worker pool is bound (non-isolated) |
| `qoltanba_trust_anchors` | gauge | — |
| `qoltanba_crl_cache_total` | counter | `result` (`hit`/`miss`) — present only when the CRL cache is enabled |
| `qoltanba_oidc_challenges`, `qoltanba_qr_sessions` | gauge | — |
| `go_*`, `process_*` | — | standard Go/process collectors |

Labels are deliberately low-cardinality — no DN/IIN/serials.

## Wiring

**Kubernetes (Helm).** The chart already annotates the Service for
`prometheus.io/scrape`. For the Prometheus Operator:

```
helm upgrade --install qoltanba deploy/helm/qoltanba \
  --set metrics.serviceMonitor=true \
  --set metrics.prometheusRule=true \
  --set metrics.dashboardConfigMap=true
```

`serviceMonitor` scrapes `/metrics`; `prometheusRule` renders `alerts.yaml`;
`dashboardConfigMap` publishes the dashboard with the `grafana_dashboard` sidecar
label so a Grafana sidecar auto-loads it.

**Plain Prometheus + Grafana.** Add `prometheus/scrape.example.yaml` to your
scrape config, point `rule_files` at `prometheus/alerts.yaml`, and import
`grafana/dashboards/qoltanba-overview.json` (pick your Prometheus datasource when
prompted).

**Try it locally.** The dev playground (`playground/compose.yaml`) brings up
Prometheus, Grafana (auto-provisioned with this dashboard and the Prometheus/Loki
datasources), Loki and Promtail against a live qoltanba on real keys.

## Known gaps (need a dedicated metric first)

- **Certificate-expiry** — ✅ covered by the certificate watcher
  (`QOLTANBA_CERTWATCH_ENABLED=true`, `CERTWATCH_DIR`): it exports
  `qoltanba_watched_cert_expiry_seconds{file,subject}`,
  `qoltanba_watched_cert_revoked` and `qoltanba_watched_cert_check_ok` for the
  certificates an operator puts under watch, and can post a webhook when one turns
  revoked or enters the expiry window. The label set is that curated watch list,
  not every certificate the service sees, so cardinality stays bounded.
- **Direct OCSP/CRL responder up/down** — approximated by `QoltanbaValidationErrorSurge`
  (server-error rate on `cert-validate` ops), not a true reachability probe.
