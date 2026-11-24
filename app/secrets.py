"""Google Cloud Secret Manager integration ensuring zero hardcoded credentials."""

from __future__ import annotations

import functools
import logging
import os
from typing import Any

try:
    from google.cloud import secretmanager
    HAS_SECRET_MANAGER = True
except ImportError:  # pragma: no cover
    secretmanager = None  # type: ignore[assignment]
    HAS_SECRET_MANAGER = False

logger = logging.getLogger("pso_arch_review.secrets")


class SecretManagerService:
    """Retrieves secrets dynamically from GCP Secret Manager or Cloud Run secret env mounts."""

    def __init__(self, project_id: str | None = None) -> None:
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None and HAS_SECRET_MANAGER:
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    @functools.lru_cache(maxsize=32)  # noqa: B019
    def get_secret(
        self,
        secret_id: str,
        version: str = "latest",
        default: str | None = None,
    ) -> str:
        """Fetch a secret from injected env vars or Google Cloud Secret Manager.

        Args:
            secret_id: Secret Manager secret name (e.g., 'ARB_TICKETING_WEBHOOK_SECRET').
            version: Secret version identifier (defaults to 'latest').
            default: Non-sensitive fallback for offline unit tests only.

        Returns:
            Resolved secret payload string.

        Raises:
            RuntimeError: If the secret is unavailable and no fallback default is supplied.
        """
        # 1. Prefer Cloud Run Secret Manager environment mount (`secret_key_ref`)
        mounted_value = os.environ.get(secret_id)
        if mounted_value:
            return mounted_value.strip()

        # 2. Fetch directly from Google Cloud Secret Manager API via ADC
        enabled = os.environ.get("ENABLE_GCP_SECRET_MANAGER", "true").lower() in ("true", "1", "yes")
        if enabled and self.project_id and HAS_SECRET_MANAGER:
            resource_name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            try:
                response = self._get_client().access_secret_version(request={"name": resource_name})
                return response.payload.data.decode("utf-8").strip()
            except Exception as exc:  # pragma: no cover - requires live GCP project
                logger.warning("Secret Manager lookup fallback for %s (%s)", secret_id, type(exc).__name__)

        if default is not None:
            return default

        raise RuntimeError(
            f"Secret '{secret_id}' not configured via Secret Manager or environment."
        )


@functools.cache
def get_secret_manager() -> SecretManagerService:
    """Return process-wide SecretManagerService singleton."""
    return SecretManagerService()
