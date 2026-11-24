output "cloud_run_service_uri" {
  description = "Deployed Cloud Run v2 endpoint for the PSO Architecture Review Agent."
  value       = google_cloud_run_v2_service.agent_service.uri
}

output "runtime_service_account_email" {
  description = "Least-privilege service account bound to the ADK runtime."
  value       = google_service_account.agent_runtime.email
}

output "firestore_session_database" {
  description = "Firestore Native database storing persistent agent sessions."
  value       = google_firestore_database.sessions.name
}

output "dlp_deidentify_template" {
  description = "Cloud DLP template used for PII redaction."
  value       = google_data_loss_prevention_deidentify_template.pii_scrubber.name
}
