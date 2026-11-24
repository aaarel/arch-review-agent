"""Strict Input/Output JSON Schemas and Guided Error Models for PSO Architecture Review Tools."""

from __future__ import annotations

import re
from enum import Enum, StrEnum
from typing import Any

try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover - lightweight fallback for bare-Python local tests
    HAS_PYDANTIC = False

    class ValidationError(ValueError):
        def __init__(self, errors: list[dict[str, Any]]) -> None:
            self._errors = errors
            super().__init__(str(errors))

        def errors(self) -> list[dict[str, Any]]:
            return self._errors

    def ConfigDict(**kwargs: Any) -> dict[str, Any]:
        return kwargs

    def Field(default: Any = ..., **kwargs: Any) -> Any:
        return {"__field__": True, "default": default, **kwargs}

    class BaseModel:
        model_config: dict[str, Any] = {"extra": "forbid"}

        def __init__(self, **data: Any) -> None:
            ann = getattr(self.__class__, "__annotations__", {})
            extra = set(data) - set(ann)
            if self.model_config.get("extra") == "forbid" and extra:
                raise ValidationError([{"loc": (k,), "msg": f"Extra field '{k}' forbidden"} for k in sorted(extra)])
            errs: list[dict[str, Any]] = []
            for name in ann:
                spec = getattr(self.__class__, name, None)
                is_spec = isinstance(spec, dict) and spec.get("__field__")
                if name in data:
                    val = data[name]
                elif is_spec and spec["default"] is not ...:
                    val = spec["default"]() if callable(spec["default"]) else spec["default"]
                elif is_spec and "default_factory" in spec:
                    val = spec["default_factory"]()
                elif not is_spec and hasattr(self.__class__, name):
                    val = getattr(self.__class__, name)
                else:
                    errs.append({"loc": (name,), "msg": f"Missing required field '{name}'"})
                    continue
                if is_spec and val is not None:
                    if isinstance(val, str):
                        if "min_length" in spec and len(val) < spec["min_length"]:
                            errs.append({"loc": (name,), "msg": f"Length must be >= {spec['min_length']}"})
                        if "max_length" in spec and len(val) > spec["max_length"]:
                            errs.append({"loc": (name,), "msg": f"Length must be <= {spec['max_length']}"})
                        if "pattern" in spec and not re.match(spec["pattern"], val):
                            errs.append({"loc": (name,), "msg": f"'{val}' does not match '{spec['pattern']}'"})
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        if "ge" in spec and val < spec["ge"]:
                            errs.append({"loc": (name,), "msg": f"Value must be >= {spec['ge']}"})
                        if "le" in spec and val > spec["le"]:
                            errs.append({"loc": (name,), "msg": f"Value must be <= {spec['le']}"})
                setattr(self, name, val)
            if errs:
                raise ValidationError(errs)

        def model_dump(self) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k in getattr(self.__class__, "__annotations__", {}):
                v = getattr(self, k)
                if isinstance(v, Enum):
                    out[k] = v.value
                elif isinstance(v, BaseModel):
                    out[k] = v.model_dump()
                elif isinstance(v, list):
                    out[k] = [i.model_dump() if isinstance(i, BaseModel) else i for i in v]
                else:
                    out[k] = v
            return out

        @classmethod
        def model_json_schema(cls) -> dict[str, Any]:
            props: dict[str, Any] = {}
            req: list[str] = []
            for k, hint in getattr(cls, "__annotations__", {}).items():
                spec = getattr(cls, k, None)
                p: dict[str, Any] = {"type": str(hint)}
                if isinstance(spec, dict) and spec.get("__field__"):
                    for sk, jk in (("description", "description"), ("pattern", "pattern"), ("min_length", "minLength"), ("max_length", "maxLength"), ("ge", "minimum"), ("le", "maximum")):
                        if sk in spec:
                            p[jk] = spec[sk]
                    if spec.get("default") is ... and "default_factory" not in spec:
                        req.append(k)
                else:
                    req.append(k)
                props[k] = p
            return {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "title": cls.__name__,
                "type": "object",
                "additionalProperties": False,
                "properties": props,
                "required": req,
            }


class ReviewSeverity(StrEnum):
    """Architecture Review Board finding severity scale."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class BlueprintEnvironment(StrEnum):
    """Target Landing Zone lifecycle environment."""

    PROD = "prod"
    STAGING = "staging"
    SANDBOX = "sandbox"


class EnforcementMode(StrEnum):
    """VPC Service Controls perimeter enforcement mode."""

    DRY_RUN = "dry_run"
    ENFORCED = "enforced"


class ControlFramework(StrEnum):
    """Supported cloud security reference frameworks."""

    CIS_GCP = "cis-gcp"
    ZERO_TRUST = "zero-trust"
    VPC_SC = "vpc-sc"


class InspectTopologyInput(BaseModel):
    """Strict input schema for `inspect_landing_zone_topology`."""

    model_config = ConfigDict(extra="forbid")

    blueprint_id: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-]{3,63}$",
        description="Kebab-case Landing Zone blueprint ID (e.g., 'fintech-payments-lz').",
    )
    environment: BlueprintEnvironment = Field(
        default=BlueprintEnvironment.PROD,
        description="Target deployment environment ('prod', 'staging', or 'sandbox').",
    )


class InspectTopologyOutput(BaseModel):
    """Strict output schema for `inspect_landing_zone_topology`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success", description="Tool status ('success').")
    blueprint_id: str = Field(..., description="Inspected Landing Zone blueprint ID.")
    environment: str = Field(..., description="Inspected environment.")
    ncc_spoke_count: int = Field(..., ge=0, description="Number of Network Connectivity Center spokes.")
    vpc_sc_mode: str = Field(..., description="Current VPC-SC posture ('none', 'dry_run', or 'enforced').")
    psc_enabled: bool = Field(..., description="Whether Private Service Connect is enabled for Google APIs.")
    public_egress_open: bool = Field(..., description="Whether unrestricted internet egress (0.0.0.0/0) is permitted.")
    exposed_assets: list[str] = Field(default_factory=list, description="Assets lacking private-only ingress/egress.")
    posture_grade: str = Field(..., description="Initial posture tier ('HARDENED', 'NEEDS_REMEDIATION', or 'EXPOSED').")


class SearchControlCatalogInput(BaseModel):
    """Strict input schema for `search_security_control_catalog`."""

    model_config = ConfigDict(extra="forbid")

    risk_query: str = Field(
        ...,
        min_length=3,
        max_length=300,
        description="Keywords describing the architectural gap (e.g., 'vpc-sc egress bigquery').",
    )
    framework: ControlFramework = Field(
        default=ControlFramework.ZERO_TRUST,
        description="Reference framework filter ('cis-gcp', 'zero-trust', or 'vpc-sc').",
    )
    max_results: int = Field(default=3, ge=1, le=10, description="Maximum controls to return (1-10).")


class SecurityControlItem(BaseModel):
    """Single grounded security control reference."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., pattern=r"^CTL-[A-Z0-9\-]+$", description="Canonical control ID.")
    framework: str = Field(..., description="Control framework identifier.")
    title: str = Field(..., description="Human-readable control title.")
    remediation_pattern: str = Field(..., description="Prescriptive Google Cloud remediation pattern.")


class SearchControlCatalogOutput(BaseModel):
    """Strict output schema for `search_security_control_catalog`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success", description="Tool status.")
    query: str = Field(..., description="Sanitized query executed.")
    total_matches: int = Field(..., ge=0, description="Number of matching controls.")
    controls: list[SecurityControlItem] = Field(default_factory=list, description="Matched control records.")


class SimulateAttackPathInput(BaseModel):
    """Strict input schema for `simulate_exfiltration_attack_path`."""

    model_config = ConfigDict(extra="forbid")

    blueprint_id: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-]{3,63}$",
        description="Target Landing Zone blueprint ID to red-team.",
    )
    threat_vector: str = Field(
        ...,
        pattern=r"^(data_exfiltration|lateral_movement|iam_privilege_escalation)$",
        description="Red-Team scenario: 'data_exfiltration', 'lateral_movement', or 'iam_privilege_escalation'.",
    )


class SimulateAttackPathOutput(BaseModel):
    """Strict output schema for `simulate_exfiltration_attack_path`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success", description="Tool status.")
    blueprint_id: str = Field(..., description="Target blueprint ID.")
    threat_vector: str = Field(..., description="Simulated threat vector.")
    exploit_viable: bool = Field(..., description="Whether an adversary can complete the kill chain.")
    blast_radius_score: int = Field(..., ge=0, le=100, description="Quantified blast radius (0-100).")
    attack_chain: list[str] = Field(default_factory=list, description="Ordered simulated adversary steps.")
    recommended_control_ids: list[str] = Field(default_factory=list, description="Mitigating control IDs.")


class RecordRiskFindingInput(BaseModel):
    """Strict input schema for `record_architecture_risk_finding`."""

    model_config = ConfigDict(extra="forbid")

    blueprint_id: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-]{3,63}$",
        description="Landing Zone blueprint ID.",
    )
    severity: ReviewSeverity = Field(..., description="Severity ('CRITICAL', 'HIGH', 'MEDIUM', or 'LOW').")
    title: str = Field(..., min_length=8, max_length=160, description="Concise finding headline.")
    control_id: str = Field(..., pattern=r"^CTL-[A-Z0-9\-]+$", description="Violated control ID (e.g., 'CTL-VPCSC-01').")
    remediation_summary: str = Field(..., min_length=15, max_length=1000, description="Concrete Blue-Team remediation steps.")
    reviewer_contact: str = Field(
        default="arb-queue@example.com",
        description="Optional reviewer email (automatically PII-scrubbed before storage).",
    )


class RecordRiskFindingOutput(BaseModel):
    """Strict output schema for `record_architecture_risk_finding`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success", description="Tool status.")
    finding_id: str = Field(..., pattern=r"^ARB-[0-9]{4,8}$", description="Assigned ARB finding ID.")
    blueprint_id: str = Field(..., description="Blueprint ID.")
    severity: str = Field(..., description="Validated severity level.")
    control_id: str = Field(..., description="Linked security control ID.")
    summary: str = Field(..., description="PII-scrubbed finding summary.")


class EnforceVpcScPerimeterInput(BaseModel):
    """Strict input schema for HITL-gated `enforce_vpc_sc_perimeter_policy`."""

    model_config = ConfigDict(extra="forbid")

    blueprint_id: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-]{3,63}$",
        description="Target Landing Zone blueprint ID.",
    )
    perimeter_name: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_\-]{3,63}$",
        description="VPC Service Controls perimeter identifier (e.g., 'prod_restricted_perimeter').",
    )
    target_mode: EnforcementMode = Field(..., description="Desired mode: 'dry_run' or 'enforced'.")
    finding_id: str = Field(..., pattern=r"^ARB-[0-9]{4,8}$", description="Authorizing ARB finding ID.")
    blast_radius_justification: str = Field(
        ...,
        min_length=15,
        max_length=500,
        description="Impact assessment confirming ingress/egress allowlists were dry-run verified.",
    )
    human_approval_token: str | None = Field(
        default=None,
        description="Explicit Human-in-the-Loop confirmation token ('APPROVED-ARB-...') required for 'enforced' mode.",
    )


class EnforceVpcScPerimeterOutput(BaseModel):
    """Strict output schema for `enforce_vpc_sc_perimeter_policy`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="'success' or 'pending_human_approval'.")
    blueprint_id: str = Field(..., description="Target blueprint ID.")
    perimeter_name: str = Field(..., description="VPC-SC perimeter name.")
    applied_mode: str = Field(..., description="Mode actually applied ('dry_run', 'enforced', or 'unchanged').")
    human_approved: bool = Field(..., description="Whether HITL confirmation was verified.")
    change_receipt_id: str | None = Field(default=None, description="Immutable change receipt ID once executed.")
    next_step: str = Field(..., description="Guidance for verification or obtaining human sign-off.")


class GuidedToolErrorResponse(BaseModel):
    """Structured error payload giving the LLM actionable self-recovery guidance."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="error", description="Always 'error'.")
    tool_name: str = Field(..., description="Tool that returned the error.")
    error_code: str = Field(..., description="Machine-readable error classification.")
    message: str = Field(..., description="Clear description of the failure.")
    validation_errors: list[dict[str, Any]] = Field(default_factory=list, description="Schema validation details.")
    recovery_instructions: str = Field(..., description="Actionable instructions for the LLM to self-correct.")
    retryable: bool = Field(default=True, description="Whether retrying with corrected arguments can succeed.")
    suggested_parameters: dict[str, Any] = Field(default_factory=dict, description="Example valid arguments.")
    suggested_next_tool: str | None = Field(default=None, description="Prerequisite or fallback tool name.")


EXPLICIT_JSON_SCHEMAS: dict[str, dict[str, Any]] = {
    model.__name__: model.model_json_schema()
    for model in (
        InspectTopologyInput,
        InspectTopologyOutput,
        SearchControlCatalogInput,
        SearchControlCatalogOutput,
        SimulateAttackPathInput,
        SimulateAttackPathOutput,
        RecordRiskFindingInput,
        RecordRiskFindingOutput,
        EnforceVpcScPerimeterInput,
        EnforceVpcScPerimeterOutput,
        GuidedToolErrorResponse,
    )
}
