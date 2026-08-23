variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "qoltanba"
}

variable "namespace" {
  description = "Kubernetes namespace to deploy into."
  type        = string
  default     = "qoltanba"
}

variable "create_namespace" {
  description = "Create the namespace if it does not exist."
  type        = bool
  default     = true
}

variable "chart" {
  description = "Chart location: a local path (default: the chart bundled in this repo) or a chart name from repository."
  type        = string
  default     = "../helm/qoltanba"
}

variable "repository" {
  description = "Helm repository URL when chart is a remote chart name (empty for a local path)."
  type        = string
  default     = ""
}

variable "chart_version" {
  description = "Chart version (only for a remote chart; empty tracks the local chart)."
  type        = string
  default     = ""
}

variable "image_repository" {
  description = "Container image repository (the binary only — Kalkan is BYOL)."
  type        = string
  default     = "qoltanba"
}

variable "image_tag" {
  description = "Container image tag (empty uses the chart appVersion)."
  type        = string
  default     = ""
}

variable "replica_count" {
  description = "Number of replicas."
  type        = number
  default     = 1
}

variable "transports" {
  description = "Which transports to enable. At least one must be true."
  type = object({
    http = bool
    grpc = bool
  })
  default = { http = true, grpc = false }
}

variable "byol" {
  description = <<-EOT
    Bring-Your-Own-Library: the Kalkan native library. mount_path/lib_file point the
    service at it; volume is the Kubernetes volume source that holds it (e.g.
    { hostPath = { path = "/opt/kalkan", type = "Directory" } } or
    { persistentVolumeClaim = { claimName = "kalkan-lib" } }). Leaving volume empty
    mounts a placeholder emptyDir and readiness will fail — you MUST supply one.
  EOT
  type = object({
    mount_path = optional(string, "/opt/kalkan")
    lib_file   = optional(string, "libkalkancryptwr-64.so")
    volume     = optional(any, {})
  })
  default = {}
}

variable "config" {
  description = "Non-secret settings → ConfigMap → env (QOLTANBA_* keys)."
  type        = map(string)
  default = {
    QOLTANBA_LOG_LEVEL             = "info"
    QOLTANBA_LOG_FORMAT            = "json"
    QOLTANBA_HTTP_ADDR             = ":8080"
    QOLTANBA_TRUST_USE_RK_REGISTRY = "true"
  }
}

variable "secret_config" {
  description = "Secret settings → Secret → env (QOLTANBA_*_PASSWORD / _PIN, etc.). Prefer extra_values with an existing Secret for production."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "metrics" {
  description = "Observability toggles. service_monitor/prometheus_rule/dashboard_config_map need the Prometheus Operator + Grafana sidecar."
  type = object({
    enabled              = optional(bool, true)
    service_monitor      = optional(bool, false)
    prometheus_rule      = optional(bool, false)
    dashboard_config_map = optional(bool, false)
  })
  default = {}
}

variable "resources" {
  description = "Container resource requests/limits (Helm values shape)."
  type        = any
  default     = null
}

variable "extra_values_yaml" {
  description = "Raw YAML merged last over the computed values — the escape hatch for any chart value not exposed above."
  type        = string
  default     = ""
}
