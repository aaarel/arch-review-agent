"""Observability: Structured JSON Logging, OpenTelemetry Tracing, Intent/Outcome Audit, and PII Redaction."""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

try:
    from google.cloud import dlp_v2
    HAS_CLOUD_DLP = True
except ImportError:  # pragma: no cover
    dlp_v2 = None  # type: ignore[assignment]
    HAS_CLOUD_DLP = False

try:
    from pythonjsonlogger.json import JsonFormatter as _BaseJsonFormatter
except ImportError:  # pragma: no cover
    _BaseJsonFormatter = logging.Formatter  # type: ignore[assignment,misc]

try:
    import google.cloud.logging as gcp_logging
    HAS_GCP_LOGGING = True
except ImportError:  # pragma: no cover
    gcp_logging = None  # type: ignore[assignment]
    HAS_GCP_LOGGING = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    HAS_OTEL = True
except ImportError:  # pragma: no cover
    trace = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    BatchSpanProcessor = None  # type: ignore[assignment]
    HAS_OTEL = False

try:
    from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
    HAS_CLOUD_TRACE = True
except ImportError:  # pragma: no cover
    CloudTraceSpanExporter = None  # type: ignore[assignment]
    HAS_CLOUD_TRACE = False


class PiiRedactor:
    """Active PII scrubbing pipeline using deterministic regexes and Google Cloud DLP."""

    _PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
        (re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"), "[REDACTED_PHONE]"),
        (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_CREDIT_CARD]"),
        (
            re.compile(r"\b(?:AIza[0-9A-Za-z\-_]{20,45}|ya29\.[0-9A-Za-z\-_]+|ghp_[A-Za-z0-9]{20,45}|sk-[A-Za-z0-9]{20,})\b"),
            "[REDACTED_API_KEY]",
        ),
    )

    def __init__(self, project_id: str | None = None, enable_cloud_dlp: bool = False) -> None:
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.enable_cloud_dlp = enable_cloud_dlp or (
            os.environ.get("ENABLE_CLOUD_DLP", "false").lower() in ("true", "1", "yes")
        )
        self._dlp_client: Any = None

    def redact_text(self, text: str) -> str:
        """Scrub PII and credentials from a string via regex + optional Cloud DLP."""
        if not text:
            return text
        scrubbed = text
        for pattern, replacement in self._PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        if self.enable_cloud_dlp and self.project_id and HAS_CLOUD_DLP:
            scrubbed = self._deidentify_with_cloud_dlp(scrubbed)
        return scrubbed

    def _deidentify_with_cloud_dlp(self, text: str) -> str:
        """Invoke Google Cloud Sensitive Data Protection (`dlp_v2.deidentify_content`)."""
        try:
            if self._dlp_client is None:
                self._dlp_client = dlp_v2.DlpServiceClient()
            response = self._dlp_client.deidentify_content(
                request={
                    "parent": f"projects/{self.project_id}/locations/global",
                    "inspect_config": {
                        "info_types": [
                            {"name": "EMAIL_ADDRESS"},
                            {"name": "PHONE_NUMBER"},
                            {"name": "US_SOCIAL_SECURITY_NUMBER"},
                            {"name": "CREDIT_CARD_NUMBER"},
                        ]
                    },
                    "deidentify_config": {
                        "info_type_transformations": {
                            "transformations": [
                                {"primitive_transformation": {"replace_with_info_type_config": {}}}
                            ]
                        }
                    },
                    "item": {"value": text},
                }
            )
            return response.item.value
        except Exception:  # pragma: no cover - live API fallback
            return text

    def redact_payload(self, data: Any) -> Any:
        """Recursively scrub PII from strings, dicts, lists, and tuples."""
        if isinstance(data, str):
            return self.redact_text(data)
        if isinstance(data, dict):
            return {str(k): self.redact_payload(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.redact_payload(v) for v in data]
        if isinstance(data, tuple):
            return tuple(self.redact_payload(v) for v in data)
        return data


pii_redactor = PiiRedactor()


class _SpanRecord:
    """Minimal span handle when running without OpenTelemetry SDK."""

    def __init__(self, name: str, trace_id: str, span_id: str, parent_id: str | None) -> None:
        self.name = name
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_id
        self.attributes: dict[str, Any] = {}
        self.status = "OK"

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = pii_redactor.redact_payload(value)


class DistributedTracer:
    """OpenTelemetry distributed tracer linking spans end-to-end from query to verdict."""

    def __init__(self, service_name: str = "pso-architecture-review-agent") -> None:
        self.service_name = service_name
        self._stack: list[_SpanRecord] = []
        self._completed: list[dict[str, Any]] = []
        self._otel_tracer = self._init_otel()

    def _init_otel(self) -> Any:
        if not HAS_OTEL:
            return None
        current = trace.get_tracer_provider()
        if not isinstance(current, TracerProvider):
            provider = TracerProvider(resource=Resource.create({"service.name": self.service_name}))
            if HAS_CLOUD_TRACE and os.environ.get("ENABLE_CLOUD_TRACE", "false").lower() == "true":
                try:
                    provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
                except Exception:  # pragma: no cover
                    pass
            trace.set_tracer_provider(provider)
        return trace.get_tracer(self.service_name)

    def current_context(self) -> dict[str, str | None]:
        """Return active `trace_id` and `span_id` for structured log correlation."""
        if HAS_OTEL and self._otel_tracer is not None:
            span = trace.get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and ctx.is_valid:
                return {"trace_id": format(ctx.trace_id, "032x"), "span_id": format(ctx.span_id, "016x")}
        if self._stack:
            top = self._stack[-1]
            return {"trace_id": top.trace_id, "span_id": top.span_id}
        return {"trace_id": None, "span_id": None}

    @contextmanager
    def start_span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
        """Start a linked parent/child span and record redacted telemetry attributes."""
        clean_attrs = pii_redactor.redact_payload(attributes or {})
        start_ns = time.time_ns()
        if HAS_OTEL and self._otel_tracer is not None:
            parent_ctx = self.current_context()
            with self._otel_tracer.start_as_current_span(name) as otel_span:
                for k, v in clean_attrs.items():
                    otel_span.set_attribute(k, json.dumps(v) if isinstance(v, (dict, list)) else str(v))
                ctx = otel_span.get_span_context()
                status = "OK"
                try:
                    yield otel_span
                except Exception as exc:
                    status = "ERROR"
                    otel_span.record_exception(exc)
                    raise
                finally:
                    self._completed.append(
                        {
                            "name": name,
                            "trace_id": format(ctx.trace_id, "032x"),
                            "span_id": format(ctx.span_id, "016x"),
                            "parent_span_id": parent_ctx["span_id"],
                            "attributes": clean_attrs,
                            "status": status,
                            "duration_ms": round((time.time_ns() - start_ns) / 1_000_000, 3),
                        }
                    )
            return

        parent = self._stack[-1] if self._stack else None
        span = _SpanRecord(
            name=name,
            trace_id=parent.trace_id if parent else uuid.uuid4().hex,
            span_id=uuid.uuid4().hex[:16],
            parent_id=parent.span_id if parent else None,
        )
        span.attributes.update(clean_attrs)
        self._stack.append(span)
        try:
            yield span
        except Exception:
            span.status = "ERROR"
            raise
        finally:
            self._stack.pop()
            self._completed.append(
                {
                    "name": span.name,
                    "trace_id": span.trace_id,
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id,
                    "attributes": span.attributes,
                    "status": span.status,
                    "duration_ms": round((time.time_ns() - start_ns) / 1_000_000, 3),
                }
            )

    def recorded_spans(self) -> list[dict[str, Any]]:
        return list(self._completed)

    def clear(self) -> None:
        self._completed.clear()


tracer = DistributedTracer()


class StructuredJsonFormatter(_BaseJsonFormatter):
    """Formats every log record as PII-redacted JSON with OpenTelemetry trace correlation."""

    def format(self, record: logging.LogRecord) -> str:
        tctx = tracer.current_context()
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": record.levelname,
            "service": "pso-architecture-review-agent",
            "logger": record.name,
            "message": pii_redactor.redact_text(record.getMessage()),
            "trace_id": getattr(record, "trace_id", None) or tctx["trace_id"],
            "span_id": getattr(record, "span_id", None) or tctx["span_id"],
            "event_phase": getattr(record, "event_phase", "SYSTEM"),
            "correlation_id": getattr(record, "correlation_id", None),
            "agent_name": getattr(record, "agent_name", None),
            "tool_name": getattr(record, "tool_name", None),
            "metadata": pii_redactor.redact_payload(getattr(record, "metadata", {})),
        }
        return json.dumps({k: v for k, v in payload.items() if v is not None}, sort_keys=True)


class IntentOutcomeAuditLogger:
    """Structured JSON audit logger recording INTENT before and OUTCOME after every action."""

    def __init__(self, logger_name: str = "pso_arch_review.audit") -> None:
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self._records: list[dict[str, Any]] = []
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(StructuredJsonFormatter())
            self.logger.addHandler(handler)
            if HAS_GCP_LOGGING and os.environ.get("ENABLE_CLOUD_LOGGING", "false").lower() == "true":
                try:
                    self.logger.addHandler(gcp_logging.Client().get_default_handler())
                except Exception:  # pragma: no cover
                    pass

    def log_intent(
        self,
        *,
        action_type: str,
        target_name: str,
        intended_inputs: dict[str, Any],
        rationale: str,
        agent_name: str = "pso_arb_coordinator",
        correlation_id: str | None = None,
    ) -> str:
        """Record the agent's declared INTENT prior to execution."""
        corr_id = correlation_id or f"corr-{uuid.uuid4().hex[:10]}"
        tctx = tracer.current_context()
        entry = {
            "event_phase": "INTENT",
            "correlation_id": corr_id,
            "agent_name": agent_name,
            "tool_name": target_name if action_type == "TOOL_CALL" else None,
            "trace_id": tctx["trace_id"],
            "span_id": tctx["span_id"],
            "metadata": {
                "action_type": action_type,
                "target_name": target_name,
                "intended_inputs": pii_redactor.redact_payload(intended_inputs),
                "rationale": pii_redactor.redact_text(rationale),
            },
        }
        self._records.append(entry)
        self.logger.info(f"[INTENT] {agent_name} -> {action_type}:{target_name}", extra=entry)
        return corr_id

    def log_outcome(
        self,
        *,
        correlation_id: str,
        action_type: str,
        target_name: str,
        actual_status: str,
        actual_output: Any,
        duration_ms: float,
        agent_name: str = "pso_arb_coordinator",
    ) -> dict[str, Any]:
        """Record the actual OUTCOME after execution, paired to INTENT via `correlation_id`."""
        tctx = tracer.current_context()
        entry = {
            "event_phase": "OUTCOME",
            "correlation_id": correlation_id,
            "agent_name": agent_name,
            "tool_name": target_name if action_type == "TOOL_CALL" else None,
            "trace_id": tctx["trace_id"],
            "span_id": tctx["span_id"],
            "metadata": {
                "action_type": action_type,
                "target_name": target_name,
                "actual_status": actual_status,
                "actual_output": pii_redactor.redact_payload(actual_output),
                "duration_ms": round(duration_ms, 3),
                "intent_matched_outcome": actual_status not in ("error", "exception"),
            },
        }
        self._records.append(entry)
        self.logger.info(f"[OUTCOME] {action_type}:{target_name} -> {actual_status}", extra=entry)
        return entry

    def audit_trail(self) -> list[dict[str, Any]]:
        return list(self._records)

    def clear(self) -> None:
        self._records.clear()


audit_logger = IntentOutcomeAuditLogger()


def trace_and_audit(action_type: str, rationale: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator adding an OpenTelemetry span and paired INTENT/OUTCOME audit logs."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            safe_kwargs = {k: v for k, v in kwargs.items() if k != "tool_context"}
            with tracer.start_span(f"tool.{func.__name__}", {"tool.name": func.__name__}) as span:
                corr_id = audit_logger.log_intent(
                    action_type=action_type,
                    target_name=func.__name__,
                    intended_inputs=safe_kwargs,
                    rationale=rationale,
                )
                try:
                    result = func(*args, **kwargs)
                    status = result.get("status", "success") if isinstance(result, dict) else "success"
                    if hasattr(span, "set_attribute"):
                        span.set_attribute("tool.status", str(status))
                    audit_logger.log_outcome(
                        correlation_id=corr_id,
                        action_type=action_type,
                        target_name=func.__name__,
                        actual_status=str(status),
                        actual_output=result,
                        duration_ms=(time.perf_counter() - start) * 1000.0,
                    )
                    return result
                except Exception as exc:
                    audit_logger.log_outcome(
                        correlation_id=corr_id,
                        action_type=action_type,
                        target_name=func.__name__,
                        actual_status="exception",
                        actual_output={"error": type(exc).__name__},
                        duration_ms=(time.perf_counter() - start) * 1000.0,
                    )
                    raise

        return wrapper

    return decorator


# ADK lifecycle callbacks for live Runner / `adk web` observability
def log_agent_intent_before_callback(callback_context: Any) -> None:
    """ADK before_agent_callback recording agent execution INTENT."""
    name = getattr(callback_context, "agent_name", "unknown_agent")
    corr_id = audit_logger.log_intent(
        action_type="AGENT_TURN",
        target_name=name,
        intended_inputs={"agent": name},
        rationale=f"Execute ADK agent '{name}' turn.",
        agent_name=name,
    )
    state = getattr(callback_context, "state", None)
    if state is not None and hasattr(state, "__setitem__"):
        state[f"_corr_{name}"] = corr_id
        state[f"_ts_{name}"] = time.perf_counter()


def log_agent_outcome_after_callback(callback_context: Any) -> None:
    """ADK after_agent_callback recording agent execution OUTCOME and latency."""
    name = getattr(callback_context, "agent_name", "unknown_agent")
    state = getattr(callback_context, "state", None)
    corr_id = state.get(f"_corr_{name}", f"corr-{name}") if hasattr(state, "get") else f"corr-{name}"
    start_ts = state.get(f"_ts_{name}") if hasattr(state, "get") else None
    elapsed = (time.perf_counter() - start_ts) * 1000.0 if isinstance(start_ts, (int, float)) else 0.0
    audit_logger.log_outcome(
        correlation_id=corr_id,
        action_type="AGENT_TURN",
        target_name=name,
        actual_status="completed",
        actual_output={"agent": name},
        duration_ms=elapsed,
        agent_name=name,
    )
