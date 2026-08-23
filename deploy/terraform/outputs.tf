output "release_name" {
  description = "The Helm release name."
  value       = helm_release.qoltanba.name
}

output "namespace" {
  description = "The namespace the release was deployed into."
  value       = helm_release.qoltanba.namespace
}

output "chart_version" {
  description = "The deployed chart version."
  value       = helm_release.qoltanba.version
}

output "app_version" {
  description = "The deployed application version."
  value       = helm_release.qoltanba.metadata[0].app_version
}
