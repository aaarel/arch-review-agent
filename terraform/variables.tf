variable "project_id" {
  type        = string
  description = "Target Google Cloud Project ID."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Google Cloud region for Cloud Run and Firestore."
}

variable "service_name" {
  type        = string
  default     = "pso-arch-review-agent"
  description = "Cloud Run service and resource name prefix."
}

variable "container_image" {
  type        = string
  description = "Artifact Registry container image URI built from Dockerfile."
}
