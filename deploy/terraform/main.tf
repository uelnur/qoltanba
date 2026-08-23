# Deploys qoltanba via its Helm chart. The Kalkan library is BYOL: set
# var.byol.volume to a real volume source that carries it, or readiness fails.
#
# Provider config (helm/kubernetes) is the caller's — configure the helm provider
# in your root module, e.g.:
#   provider "helm" { kubernetes { config_path = "~/.kube/config" } }

locals {
  # Chart values, assembled from the typed inputs. Nulls are pruned by yamlencode
  # only when absent, so we build the map conditionally.
  values = merge(
    {
      replicaCount = var.replica_count
      image = merge(
        { repository = var.image_repository },
        var.image_tag == "" ? {} : { tag = var.image_tag },
      )
      transports = {
        http = var.transports.http
        grpc = var.transports.grpc
      }
      byol = {
        mountPath = var.byol.mount_path
        libFile   = var.byol.lib_file
        volume    = var.byol.volume
      }
      config       = var.config
      secretConfig = var.secret_config
      metrics = {
        enabled            = var.metrics.enabled
        serviceMonitor     = var.metrics.service_monitor
        prometheusRule     = var.metrics.prometheus_rule
        dashboardConfigMap = var.metrics.dashboard_config_map
      }
    },
    var.resources == null ? {} : { resources = var.resources },
  )
}

resource "helm_release" "qoltanba" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace

  chart      = var.chart
  repository = var.repository == "" ? null : var.repository
  version    = var.chart_version == "" ? null : var.chart_version

  values = compact([
    yamlencode(local.values),
    var.extra_values_yaml,
  ])
}
