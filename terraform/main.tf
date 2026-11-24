terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable required Google Cloud AgentOps, Security, and Observability APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "firestore.googleapis.com",
    "discoveryengine.googleapis.com",
    "dlp.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "modelarmor.googleapis.com",
  ])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# 2. Dedicated least-privilege runtime service account
resource "google_service_account" "agent_runtime" {
  account_id   = "${var.service_name}-sa"
  display_name = "PSO Architecture Review Agent Runtime SA"
}

resource "google_project_iam_member" "agent_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/datastore.user",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
    "roles/secretmanager.secretAccessor",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
  ])

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.agent_runtime.email}"
}

# 3. Secret Manager secrets (zero hardcoded credentials)
resource "google_secret_manager_secret" "arb_ticketing_webhook" {
  secret_id = "ARB_TICKETING_WEBHOOK_SECRET"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "vpcsc_deployer_token" {
  secret_id = "VPCSC_POLICY_DEPLOYER_TOKEN"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# 4. Persistent session state database (Firestore Native)
resource "google_firestore_database" "sessions" {
  project     = var.project_id
  name        = "${var.service_name}-sessions"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
  depends_on  = [google_project_service.apis]
}

# 5. Cloud DLP de-identification template for active PII redaction
resource "google_data_loss_prevention_deidentify_template" "pii_scrubber" {
  parent       = "projects/${var.project_id}/locations/global"
  display_name = "PSO ARB Agent PII Scrubber"
  description  = "Redacts emails, phone numbers, SSNs, and credit card numbers before log/memory persistence."

  deidentify_config {
    info_type_transformations {
      transformations {
        info_types {
          name = "EMAIL_ADDRESS"
        }
        info_types {
          name = "PHONE_NUMBER"
        }
        info_types {
          name = "US_SOCIAL_SECURITY_NUMBER"
        }
        info_types {
          name = "CREDIT_CARD_NUMBER"
        }
        primitive_transformation {
          replace_with_info_type_config = true
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# 6. Cloud Run v2 service hosting the ADK API server
resource "google_cloud_run_v2_service" "agent_service" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.agent_runtime.email

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = var.container_image

      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "ENABLE_CLOUD_DLP"
        value = "true"
      }
      env {
        name  = "ENABLE_CLOUD_TRACE"
        value = "true"
      }
      env {
        name  = "ENABLE_CLOUD_LOGGING"
        value = "true"
      }
      env {
        name  = "ENABLE_FIRESTORE_SESSIONS"
        value = "true"
      }
      env {
        name = "ARB_TICKETING_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.arb_ticketing_webhook.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "VPCSC_POLICY_DEPLOYER_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.vpcsc_deployer_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_firestore_database.sessions,
  ]
}
