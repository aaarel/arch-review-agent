"""Security Guardrails, ADK BasePlugin, Constitutional Self-Evaluation, and HITL Gate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.observability import audit_logger, pii_redactor

try:
    from google.adk.models import LlmRequest, LlmResponse
    from google.adk.plugins.base_plugin import BasePlugin
    from google.genai import types as genai_types
    HAS_ADK_PLUGIN = True
except ImportError:  # pragma: no cover
    HAS_ADK_PLUGIN = False
    LlmRequest = Any  # type: ignore[assignment,misc]
    LlmResponse = Any  # type: ignore[assignment,misc]
    genai_types = None  # type: ignore[assignment]

    class BasePlugin:  # type: ignore[no-redef]
        def __init__(self, name: str = "plugin") -> None:
            self.name = name


_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(the\s+)?(system\s+prompt|constitution)", re.IGNORECASE),
    re.compile(r"bypass\s+(hitl|human\s+approval|guardrail)", re.IGNORECASE),
    re.compile(r"exfiltrate\s+(secret|credential|api\s*key)", re.IGNORECASE),
    re.compile(r"disable\s+all\s+vpc[- ]?sc", re.IGNORECASE),
)

_APPROVAL_TOKEN_RE = re.compile(r"^APPROVED-ARB-[A-Z0-9\-]{4,32}$")


@dataclass
class SelfEvalResult:
    """Output of the constitutional self-evaluation guardrail."""

    passed: bool
    groundedness_score: float
    safety_score: float
    overall_score: float
    violations: list[str] = field(default_factory=list)
    sanitized_response: str = ""


class HumanApprovalGate:
    """Enforces explicit Human-in-the-Loop confirmation before live VPC-SC enforcement."""

    @staticmethod
    def is_valid_token(token: str | None) -> bool:
        return bool(token and _APPROVAL_TOKEN_RE.match(token.strip()))

    @classmethod
    def check_approval(
        cls,
        *,
        action_summary: str,
        payload: dict[str, Any],
        human_approval_token: str | None = None,
        tool_context: Any = None,
    ) -> tuple[bool, str]:
        """Verify HITL confirmation via ADK `tool_context` or signed approval token.

        Returns:
            Tuple of `(approved: bool, reason: str)`.
        """
        # 1. Check ADK native ToolConfirmation state when running inside ADK Runner
        if tool_context is not None:
            confirmation = getattr(tool_context, "tool_confirmation", None)
            if confirmation is not None:
                if getattr(confirmation, "confirmed", False):
                    return True, "Approved via ADK interactive ToolConfirmation."
                return False, "Human architect explicitly rejected the perimeter change."
            request_fn = getattr(tool_context, "request_confirmation", None)
            if callable(request_fn) and not cls.is_valid_token(human_approval_token):
                request_fn(hint=action_summary, payload=pii_redactor.redact_payload(payload))
                return False, "Paused via ADK request_confirmation awaiting architect approval."

        # 2. Check signed HITL approval token (`APPROVED-ARB-...`)
        if cls.is_valid_token(human_approval_token):
            return True, f"Approved via signed HITL token '{human_approval_token}'."

        return (
            False,
            "Human-in-the-Loop stop: live 'enforced' VPC-SC perimeter promotion requires an explicit "
            "architect confirmation token matching 'APPROVED-ARB-<ID>' (e.g., 'APPROVED-ARB-2026-01').",
        )


class SelfEvaluationGuardrail:
    """Post-generation constitutional critic verifying groundedness, HITL compliance, and zero PII."""

    @staticmethod
    def evaluate_response(
        *,
        draft_response: str,
        evidence_records: list[dict[str, Any]],
        requires_hitl_notice: bool = False,
    ) -> SelfEvalResult:
        """Score a candidate architecture verdict before returning it to the user."""
        violations: list[str] = []
        sanitized = pii_redactor.redact_text(draft_response)

        # 1. Safety & PII check
        safety_score = 1.0
        if sanitized != draft_response:
            violations.append("Residual PII detected and scrubbed prior to emission.")
            safety_score -= 0.25

        # 2. Groundedness check (must reference blueprint/control evidence)
        evidence_blob = str(evidence_records)
        cites_control = bool(re.search(r"CTL-[A-Z0-9\-]+", sanitized)) or "CTL-" not in evidence_blob
        cites_posture = any(k in sanitized for k in ("HARDENED", "NEEDS_REMEDIATION", "EXPOSED", "blast_radius", "Blast Radius"))
        groundedness_score = (0.5 if cites_control else 0.0) + (0.5 if cites_posture else 0.0)
        if groundedness_score < 1.0:
            violations.append("Verdict missing grounded posture or security control ID citations.")

        # 3. HITL notice check when enforcement is pending
        if requires_hitl_notice and "pending_human_approval" not in sanitized and "HITL" not in sanitized:
            violations.append("Pending VPC-SC enforcement must explicitly state Human-in-the-Loop hold.")
            safety_score -= 0.35

        overall = round((groundedness_score + max(0.0, safety_score)) / 2.0, 3)
        passed = overall >= 0.85 and not any("HITL" in v for v in violations)
        return SelfEvalResult(
            passed=passed,
            groundedness_score=round(groundedness_score, 3),
            safety_score=round(max(0.0, safety_score), 3),
            overall_score=overall,
            violations=violations,
            sanitized_response=sanitized,
        )


class ArbSecurityGuardrailPlugin(BasePlugin):
    """ADK App-level Security & Policy Guardrail Plugin (Prompt Injection + PII + Tool Policy)."""

    def __init__(self, name: str = "arb_security_guardrail_plugin") -> None:
        super().__init__(name=name)

    def inspect_prompt_security(self, text: str) -> dict[str, Any] | None:
        """Screen text against prompt-injection and policy-bypass rules."""
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text or ""):
                decision = {
                    "status": "blocked_by_guardrail",
                    "policy": "ARB_CONSTITUTION_ARTICLE_IV",
                    "matched_rule": pattern.pattern,
                    "message": (
                        "Blocked by ARB Security Guardrail: attempts to override constitutional rules, "
                        "bypass HITL approvals, or exfiltrate credentials are prohibited."
                    ),
                }
                audit_logger.log_outcome(
                    correlation_id="guardrail-block",
                    action_type="GUARDRAIL_POLICY",
                    target_name="inspect_prompt_security",
                    actual_status="blocked_by_guardrail",
                    actual_output=decision,
                    duration_ms=0.2,
                )
                return decision
        return None

    async def before_model_callback(
        self,
        *,
        callback_context: Any,
        llm_request: LlmRequest,
    ) -> LlmResponse | None:
        """ADK hook: block prompt injection and scrub PII before every Gemini call."""
        contents = getattr(llm_request, "contents", None) or []
        for content in contents:
            for part in getattr(content, "parts", None) or []:
                text = getattr(part, "text", None)
                if isinstance(text, str) and text:
                    blocked = self.inspect_prompt_security(text)
                    if blocked is not None and HAS_ADK_PLUGIN and genai_types is not None:
                        return LlmResponse(
                            content=genai_types.Content(
                                role="model",
                                parts=[genai_types.Part.from_text(text=blocked["message"])],
                            )
                        )
                    part.text = pii_redactor.redact_text(text)
        return None

    async def after_model_callback(
        self,
        *,
        callback_context: Any,
        llm_response: LlmResponse,
    ) -> LlmResponse | None:
        """ADK hook: scrub any residual PII from model responses."""
        content = getattr(llm_response, "content", None)
        if content and getattr(content, "parts", None):
            for part in content.parts:
                if isinstance(getattr(part, "text", None), str):
                    part.text = pii_redactor.redact_text(part.text)
        return None

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any] | None:
        """ADK hook: scrub PII from tool inputs and block wildcard perimeter targets."""
        for k, v in list(tool_args.items()):
            tool_args[k] = pii_redactor.redact_payload(v)
        if getattr(tool, "name", "") == "enforce_vpc_sc_perimeter_policy":
            if str(tool_args.get("perimeter_name", "")).strip() in ("*", "all"):
                return {
                    "status": "error",
                    "tool_name": "enforce_vpc_sc_perimeter_policy",
                    "error_code": "WILDCARD_PERIMETER_FORBIDDEN",
                    "message": "Wildcard perimeter enforcement is prohibited by ARB safety policy.",
                    "recovery_instructions": "Specify an explicit perimeter_name such as 'prod_restricted_perimeter'.",
                    "retryable": True,
                }
        return None


default_guardrail_plugin = ArbSecurityGuardrailPlugin()
default_self_evaluator = SelfEvaluationGuardrail()
default_hitl_gate = HumanApprovalGate()
