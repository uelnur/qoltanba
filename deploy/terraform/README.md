# Terraform module — qoltanba on Kubernetes

Thin wrapper over the bundled Helm chart (`deploy/helm/qoltanba`) so you can manage
qoltanba as Terraform state. The Kalkan library stays **Bring-Your-Own** — you must
point `byol.volume` at a volume source that carries it.

## Usage

```hcl
provider "helm" {
  kubernetes {
    config_path = "~/.kube/config"
  }
}

module "qoltanba" {
  source = "github.com/uelnur/qoltanba//deploy/terraform"

  namespace = "qoltanba"

  image_repository = "registry.example.com/qoltanba"
  image_tag        = "1.4.0"

  # BYOL: a hostPath (single node) or a PVC that holds libkalkancryptwr-64.so.
  byol = {
    volume = {
      hostPath = { path = "/opt/kalkan", type = "Directory" }
    }
  }

  config = {
    QOLTANBA_LOG_LEVEL             = "info"
    QOLTANBA_LOG_FORMAT            = "json"
    QOLTANBA_HTTP_ADDR             = ":8080"
    QOLTANBA_TRUST_USE_RK_REGISTRY = "true"
  }

  # Observability (needs the Prometheus Operator + a Grafana sidecar):
  metrics = {
    enabled              = true
    service_monitor      = true
    prometheus_rule      = true
    dashboard_config_map = true
  }
}
```

`source` above uses the module over the repo; for local development set
`source = "../helm/..."`-style paths or clone and reference the folder. The chart
itself defaults to the in-repo path via `var.chart`.

## Inputs

See `variables.tf`. The common ones: `namespace`, `image_repository`/`image_tag`,
`replica_count`, `transports`, `byol`, `config`, `secret_config`, `metrics`,
`resources`. Anything not exposed goes through `extra_values_yaml` (raw YAML merged
last).

## Notes

- Configure the `helm` (and `kubernetes`) provider in your root module — this module
  does not.
- `metrics.service_monitor` / `prometheus_rule` require the Prometheus Operator CRDs;
  `dashboard_config_map` requires the Grafana dashboard sidecar. Without them, leave
  these `false` and scrape via the Service annotations the chart already sets.
- For production secrets, prefer referencing an existing Kubernetes Secret through
  `extra_values_yaml` (`extraEnvFrom`) over `secret_config`.
