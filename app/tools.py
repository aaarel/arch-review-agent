"""PSO Architecture Review Tools with Strict Schemas, Guided Error Recovery, and HITL Hooks."""

from __future__ import annotations

import hashlib
from typing import Any

from app.guardrails import default_hitl_gate
from app.observability import pii_redactor, trace_and_audit
from app.schemas import (
    BlueprintEnvironment,
    ControlFramework,
    EnforcementMode,
    EnforceVpcScPerimeterInput,
    EnforceVpcScPerimeterOutput,
    GuidedToolErrorResponse,
    InspectTopologyInput,
    InspectTopologyOutput,
    RecordRiskFindingInput,
    RecordRiskFindingOutput,
    ReviewSeverity,
    SearchControlCatalogInput,
    SearchControlCatalogOutput,
    SecurityControlItem,
    SimulateAttackPathInput,
    SimulateAttackPathOutput,
    ValidationError,
)
from app.secrets import get_secret_manager

try:
    from google.adk.tools.function_tool import FunctionTool
    from google.adk.tools.tool_context import ToolContext
    HAS_ADK_TOOLS = True
except ImportError:  # pragma: no cover
    HAS_ADK_TOOLS = False
    ToolContext = Any  # type: ignore[assignment,misc]

    class FunctionTool:  # type: ignore[no-redef]
        def __init__(self, func: Any, require_confirmation: bool = False) -> None:
            self.func = func
            self.name = func.__name__
            self._require_confirmation = require_confirmation
            self.require_confirmation = require_confirmation

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.func(*args, **kwargs)


# Synthetic, public-safe reference Landing Zone blueprints
_BLUEPRINT_CATALOG: dict[str, dict[str, Any]] = {
    "fintech-payments-lz": {
        "ncc_spoke_count": 6,
        "vpc_sc_mode": "dry_run",
        "psc_enabled": True,
        "public_egress_open": True,
        "exposed_assets": ["bigquery-settlement-dataset", "gcs-cardholder-staging"],
        "posture_grade": "EXPOSED",
    },
    "healthcare-analytics-lz": {
        "ncc_spoke_count": 4,
        "vpc_sc_mode": "enforced",
        "psc_enabled": True,
        "public_egress_open": False,
        "exposed_assets": [],
        "posture_grade": "HARDENED",
    },
    "retail-multicloud-lz": {
        "ncc_spoke_count": 9,
        "vpc_sc_mode": "none",
        "psc_enabled": False,
        "public_egress_open": True,
        "exposed_assets": ["vertex-ai-feature-store", "cloud-sql-orders-primary"],
        "posture_grade": "NEEDS_REMEDIATION",
    },
}

# Grounded Google Cloud Zero-Trust & CIS control catalog
_CONTROL_CATALOG: list[SecurityControlItem] = [
    SecurityControlItem(
        control_id="CTL-VPCSC-01",
        framework="vpc-sc",
        title="Enforce VPC Service Controls Perimeter on Restricted Data APIs",
        remediation_pattern="Promote dry-run perimeter to enforced mode covering BigQuery, Cloud Storage, and Vertex AI after verifying ingress/egress allowlists.",
    ),
    SecurityControlItem(
        control_id="CTL-NET-02",
        framework="zero-trust",
        title="Block Unrestricted Internet Egress & Enforce Hub Inspection",
        remediation_pattern="Remove default 0.0.0.0/0 internet gateway routes from spokes; route egress through Cloud NGFW Enterprise / Secure Web Proxy in the NCC Hub.",
    ),
    SecurityControlItem(
        control_id="CTL-PSC-03",
        framework="zero-trust",
        title="Route Google APIs over Private Service Connect (PSC) Endpoints",
        remediation_pattern="Deploy PSC Google APIs bundle (`vpc-sc`) in each spoke VPC and configure Cloud DNS response policies for `*.googleapis.com`.",
    ),
    SecurityControlItem(
        control_id="CTL-IAM-04",
        framework="cis-gcp",
        title="Disable Static Service Account Keys via Organization Policy",
        remediation_pattern="Enforce `constraints/iam.disableServiceAccountKeyCreation` and use Workload Identity Federation (OIDC) for CI/CD.",
    ),
]


@trace_and_audit("TOOL_CALL", "Inspect Landing Zone NCC topology, VPC-SC posture, and egress exposure.")
def inspect_landing_zone_topology(
    blueprint_id: str,
    environment: str = "prod",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Inspect a Google Cloud Landing Zone blueprint's network and Zero-Trust security posture.

    Call this tool first during an Architecture Review Board session to gather grounded facts
    about NCC spoke segmentation, VPC Service Controls mode, Private Service Connect adoption,
    internet egress paths, and exposed data assets.

    Args:
        blueprint_id: Lowercase kebab-case Landing Zone blueprint identifier. Registered
            blueprints are `'fintech-payments-lz'`, `'healthcare-analytics-lz'`, and
            `'retail-multicloud-lz'`.
        environment: Target lifecycle environment (`'prod'`, `'staging'`, or `'sandbox'`).
            Defaults to `'prod'`.

    Returns:
        A dict conforming to `InspectTopologyOutput` with `ncc_spoke_count`, `vpc_sc_mode`,
        `psc_enabled`, `public_egress_open`, `exposed_assets`, and `posture_grade`, or a
        `GuidedToolErrorResponse` dict with `recovery_instructions` if validation fails.
    """
    try:
        validated = InspectTopologyInput(
            blueprint_id=blueprint_id.strip().lower(),
            environment=BlueprintEnvironment(environment.strip().lower()),
        )
    except (ValidationError, ValueError) as exc:
        return GuidedToolErrorResponse(
            tool_name="inspect_landing_zone_topology",
            error_code="INVALID_TOPOLOGY_ARGS",
            message=f"Topology inspection arguments failed validation: {exc}",
            recovery_instructions=(
                "Pass a registered kebab-case 'blueprint_id' from "
                f"{sorted(_BLUEPRINT_CATALOG)} and 'environment' in ['prod', 'staging', 'sandbox']."
            ),
            suggested_parameters={"blueprint_id": "fintech-payments-lz", "environment": "prod"},
        ).model_dump()

    record = _BLUEPRINT_CATALOG.get(validated.blueprint_id)
    if record is None:
        return GuidedToolErrorResponse(
            tool_name="inspect_landing_zone_topology",
            error_code="BLUEPRINT_NOT_FOUND",
            message=f"Blueprint '{validated.blueprint_id}' does not exist in the ARB registry.",
            recovery_instructions=f"Retry with one of the known blueprints: {sorted(_BLUEPRINT_CATALOG)}.",
            suggested_parameters={"blueprint_id": sorted(_BLUEPRINT_CATALOG)[0], "environment": validated.environment.value},
        ).model_dump()

    output = InspectTopologyOutput(
        blueprint_id=validated.blueprint_id,
        environment=validated.environment.value,
        **record,
    ).model_dump()
    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["latest_topology"] = output
    return output


@trace_and_audit("TOOL_CALL", "Retrieve grounded CIS, Zero-Trust, and VPC-SC security controls.")
def search_security_control_catalog(
    risk_query: str,
    framework: str = "zero-trust",
    max_results: int = 3,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Search the PSO security control catalog for grounded Zero-Trust and CIS GCP patterns.

    Use this tool alongside `inspect_landing_zone_topology` to ground Blue-Team recommendations
    in canonical control IDs (`CTL-VPCSC-01`, `CTL-NET-02`, `CTL-PSC-03`, `CTL-IAM-04`).

    Args:
        risk_query: Space-separated keywords describing the architectural risk (3–300 chars),
            e.g., `'vpc-sc egress bigquery psc'`.
        framework: Control framework filter (`'cis-gcp'`, `'zero-trust'`, or `'vpc-sc'`).
            Defaults to `'zero-trust'`.
        max_results: Maximum control entries to return (1 to 10). Defaults to 3.

    Returns:
        A dict conforming to `SearchControlCatalogOutput` containing matched `controls`, or
        a `GuidedToolErrorResponse` dict with corrective guidance if arguments are invalid.
    """
    try:
        validated = SearchControlCatalogInput(
            risk_query=pii_redactor.redact_text(risk_query.strip()),
            framework=ControlFramework(framework.strip().lower()),
            max_results=max_results,
        )
    except (ValidationError, ValueError) as exc:
        return GuidedToolErrorResponse(
            tool_name="search_security_control_catalog",
            error_code="INVALID_CONTROL_QUERY",
            message=f"Security control query failed validation: {exc}",
            recovery_instructions="Provide a 'risk_query' (>=3 chars), 'framework' in ['cis-gcp', 'zero-trust', 'vpc-sc'], and 'max_results' 1..10.",
            suggested_parameters={"risk_query": "vpc-sc egress perimeter", "framework": "vpc-sc", "max_results": 3},
        ).model_dump()

    tokens = {tok.lower() for tok in validated.risk_query.replace("-", " ").split() if len(tok) >= 2}
    scored: list[tuple[int, SecurityControlItem]] = []
    for item in _CONTROL_CATALOG:
        haystack = f"{item.control_id} {item.framework} {item.title} {item.remediation_pattern}".lower()
        score = sum(1 for t in tokens if t in haystack) + (1 if item.framework == validated.framework.value else 0)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    matched = [item for _, item in scored[: validated.max_results]] or _CONTROL_CATALOG[:2]

    output = SearchControlCatalogOutput(
        query=validated.risk_query,
        total_matches=len(matched),
        controls=matched,
    ).model_dump()
    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["matched_controls"] = output["controls"]
    return output


@trace_and_audit("TOOL_CALL", "Run Red-Team attack path simulation against a Landing Zone blueprint.")
def simulate_exfiltration_attack_path(
    blueprint_id: str,
    threat_vector: str = "data_exfiltration",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Simulate a Red-Team adversary attack path against a Landing Zone blueprint.

    Evaluates whether an attacker with compromised workload credentials can exfiltrate data,
    move laterally across NCC spokes, or escalate IAM privileges given the blueprint's live
    VPC-SC, PSC, and egress controls.

    Args:
        blueprint_id: Target kebab-case Landing Zone blueprint identifier (e.g., `'fintech-payments-lz'`).
        threat_vector: Attack scenario to simulate. Must be one of `'data_exfiltration'`,
            `'lateral_movement'`, or `'iam_privilege_escalation'`. Defaults to `'data_exfiltration'`.

    Returns:
        A dict conforming to `SimulateAttackPathOutput` with `exploit_viable`,
        `blast_radius_score` (0–100), `attack_chain`, and `recommended_control_ids`, or a
        `GuidedToolErrorResponse` dict if validation fails.
    """
    try:
        validated = SimulateAttackPathInput(
            blueprint_id=blueprint_id.strip().lower(),
            threat_vector=threat_vector.strip().lower(),
        )
    except ValidationError as exc:
        return GuidedToolErrorResponse(
            tool_name="simulate_exfiltration_attack_path",
            error_code="INVALID_ATTACK_SIMULATION_ARGS",
            message=f"Attack simulation parameters invalid: {exc}",
            recovery_instructions=(
                "Use a valid 'blueprint_id' and set 'threat_vector' to one of "
                "['data_exfiltration', 'lateral_movement', 'iam_privilege_escalation']."
            ),
            suggested_parameters={"blueprint_id": "fintech-payments-lz", "threat_vector": "data_exfiltration"},
            suggested_next_tool="inspect_landing_zone_topology",
        ).model_dump()

    bp = _BLUEPRINT_CATALOG.get(validated.blueprint_id)
    if bp is None:
        return GuidedToolErrorResponse(
            tool_name="simulate_exfiltration_attack_path",
            error_code="BLUEPRINT_NOT_FOUND",
            message=f"Cannot red-team unknown blueprint '{validated.blueprint_id}'.",
            recovery_instructions=f"Inspect a valid blueprint first: {sorted(_BLUEPRINT_CATALOG)}.",
            suggested_next_tool="inspect_landing_zone_topology",
        ).model_dump()

    if bp["vpc_sc_mode"] == "enforced" and not bp["public_egress_open"]:
        output = SimulateAttackPathOutput(
            blueprint_id=validated.blueprint_id,
            threat_vector=validated.threat_vector,
            exploit_viable=False,
            blast_radius_score=12,
            attack_chain=[
                "1. Compromised spoke workload attempts API call to external attacker project.",
                "2. BLOCKED by enforced VPC Service Controls perimeter & restricted PSC endpoint.",
            ],
            recommended_control_ids=["CTL-VPCSC-01", "CTL-PSC-03"],
        ).model_dump()
    else:
        controls = ["CTL-VPCSC-01", "CTL-NET-02"] + ([] if bp["psc_enabled"] else ["CTL-PSC-03"])
        output = SimulateAttackPathOutput(
            blueprint_id=validated.blueprint_id,
            threat_vector=validated.threat_vector,
            exploit_viable=True,
            blast_radius_score=88 if bp["vpc_sc_mode"] == "none" else 76,
            attack_chain=[
                f"1. Adversary compromises spoke workload in '{validated.blueprint_id}'.",
                f"2. VPC-SC is '{bp['vpc_sc_mode']}' (non-blocking) and public egress is open.",
                f"3. Sensitive assets ({', '.join(bp['exposed_assets'])}) copied to external bucket.",
            ],
            recommended_control_ids=controls,
        ).model_dump()

    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["red_team_simulation"] = output
    return output


@trace_and_audit("TOOL_CALL", "Record a formal PII-scrubbed Architecture Review Board risk finding.")
def record_architecture_risk_finding(
    blueprint_id: str,
    severity: str,
    title: str,
    control_id: str,
    remediation_summary: str,
    reviewer_contact: str = "arb-queue@example.com",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Record a formal Architecture Review Board (ARB) risk finding ticket.

    Authenticates against the ARB tracker webhook via Google Cloud Secret Manager (zero
    hardcoded API keys) and scrubs PII from `title`, `remediation_summary`, and
    `reviewer_contact` prior to persistence.

    Args:
        blueprint_id: Target Landing Zone blueprint ID (e.g., `'fintech-payments-lz'`).
        severity: Risk severity (`'CRITICAL'`, `'HIGH'`, `'MEDIUM'`, or `'LOW'`).
        title: Concise finding headline (8–160 characters).
        control_id: Violated control identifier matching `^CTL-[A-Z0-9\\-]+$` (e.g., `'CTL-VPCSC-01'`).
        remediation_summary: Grounded Blue-Team remediation steps (15–1000 characters).
        reviewer_contact: Contact email of reviewing architect (automatically PII-scrubbed).

    Returns:
        A dict conforming to `RecordRiskFindingOutput` containing the assigned `finding_id`
        (`ARB-XXXX`), or a `GuidedToolErrorResponse` dict if schema validation fails.
    """
    try:
        validated = RecordRiskFindingInput(
            blueprint_id=blueprint_id.strip().lower(),
            severity=ReviewSeverity(severity.strip().upper()),
            title=pii_redactor.redact_text(title.strip()),
            control_id=control_id.strip().upper(),
            remediation_summary=pii_redactor.redact_text(remediation_summary.strip()),
            reviewer_contact=pii_redactor.redact_text(reviewer_contact.strip()),
        )
    except (ValidationError, ValueError) as exc:
        return GuidedToolErrorResponse(
            tool_name="record_architecture_risk_finding",
            error_code="INVALID_RISK_FINDING_ARGS",
            message=f"Risk finding validation failed: {exc}",
            recovery_instructions=(
                "Ensure 'severity' is in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], 'control_id' "
                "matches 'CTL-...', 'title' is >=8 chars, and 'remediation_summary' is >=15 chars."
            ),
            suggested_parameters={
                "blueprint_id": "fintech-payments-lz",
                "severity": "CRITICAL",
                "title": "VPC-SC perimeter stuck in dry-run with open internet egress",
                "control_id": "CTL-VPCSC-01",
                "remediation_summary": "Verify dry-run access logs and promote VPC-SC perimeter to enforced mode.",
            },
        ).model_dump()

    webhook_token = get_secret_manager().get_secret(
        "ARB_TICKETING_WEBHOOK_SECRET",
        default="sm-managed-local-test-token",
    )
    digest = int(hashlib.sha256(f"{validated.blueprint_id}:{validated.control_id}:{webhook_token[:4]}".encode()).hexdigest()[:4], 16)
    finding_id = f"ARB-{1000 + (digest % 8999)}"

    output = RecordRiskFindingOutput(
        finding_id=finding_id,
        blueprint_id=validated.blueprint_id,
        severity=validated.severity.value,
        control_id=validated.control_id,
        summary=f"[{validated.severity.value}] {validated.title} ({validated.control_id})",
    ).model_dump()
    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["active_finding_id"] = finding_id
    return output


@trace_and_audit("TOOL_CALL", "Promote or update a VPC Service Controls perimeter with HITL confirmation.")
def enforce_vpc_sc_perimeter_policy(
    blueprint_id: str,
    perimeter_name: str,
    target_mode: str,
    finding_id: str,
    blast_radius_justification: str,
    human_approval_token: str | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Promote a VPC Service Controls perimeter policy with mandatory Human-in-the-Loop approval.

    HIGH-STAKES GOVERNANCE ACTION: Switching a perimeter to `'enforced'` mode immediately
    blocks non-compliant API traffic. This tool enforces a hard Human-in-the-Loop (HITL) stop
    requiring either ADK `ToolConfirmation` or a signed `'APPROVED-ARB-<ID>'` token before
    applying `'enforced'` mode.

    Args:
        blueprint_id: Target Landing Zone blueprint identifier (e.g., `'fintech-payments-lz'`).
        perimeter_name: Explicit VPC-SC perimeter name (e.g., `'prod_restricted_perimeter'`).
        target_mode: Desired enforcement mode (`'dry_run'` or `'enforced'`).
        finding_id: Authorizing ARB finding ID matching `^ARB-[0-9]{4,8}$` from
            `record_architecture_risk_finding`.
        blast_radius_justification: Impact assessment confirming dry-run logs are clean (15–500 chars).
        human_approval_token: Mandatory signed HITL confirmation token (`'APPROVED-ARB-...'`)
            when `target_mode == 'enforced'`.

    Returns:
        A dict conforming to `EnforceVpcScPerimeterOutput` with `status='pending_human_approval'`
        until confirmed, or `status='success'` with an immutable `change_receipt_id` once approved.
    """
    try:
        validated = EnforceVpcScPerimeterInput(
            blueprint_id=blueprint_id.strip().lower(),
            perimeter_name=perimeter_name.strip().lower(),
            target_mode=EnforcementMode(target_mode.strip().lower()),
            finding_id=finding_id.strip().upper(),
            blast_radius_justification=pii_redactor.redact_text(blast_radius_justification.strip()),
            human_approval_token=human_approval_token,
        )
    except (ValidationError, ValueError) as exc:
        return GuidedToolErrorResponse(
            tool_name="enforce_vpc_sc_perimeter_policy",
            error_code="INVALID_PERIMETER_ENFORCEMENT_ARGS",
            message=f"VPC-SC perimeter enforcement arguments invalid: {exc}",
            recovery_instructions=(
                "Call `record_architecture_risk_finding` first to obtain a valid 'ARB-XXXX' "
                "finding_id, set 'target_mode' to 'dry_run' or 'enforced', and include a "
                "15+ char 'blast_radius_justification'."
            ),
            suggested_next_tool="record_architecture_risk_finding",
        ).model_dump()

    # Enforce mandatory Human-in-the-Loop stop for live 'enforced' mode
    if validated.target_mode == EnforcementMode.ENFORCED:
        approved, reason = default_hitl_gate.check_approval(
            action_summary=(
                f"Approve LIVE VPC-SC enforcement on '{validated.perimeter_name}' "
                f"for '{validated.blueprint_id}' (Finding {validated.finding_id})?"
            ),
            payload=validated.model_dump(),
            human_approval_token=validated.human_approval_token,
            tool_context=tool_context,
        )
        if not approved:
            return EnforceVpcScPerimeterOutput(
                status="pending_human_approval",
                blueprint_id=validated.blueprint_id,
                perimeter_name=validated.perimeter_name,
                applied_mode="unchanged",
                human_approved=False,
                change_receipt_id=None,
                next_step=reason,
            ).model_dump()

    _deploy_secret = get_secret_manager().get_secret(
        "VPCSC_POLICY_DEPLOYER_TOKEN",
        default="sm-managed-deployer-token",
    )
    receipt = "CHG-" + hashlib.sha256(
        f"{validated.perimeter_name}:{validated.finding_id}:{_deploy_secret[:4]}".encode()
    ).hexdigest()[:8].upper()

    return EnforceVpcScPerimeterOutput(
        status="success",
        blueprint_id=validated.blueprint_id,
        perimeter_name=validated.perimeter_name,
        applied_mode=validated.target_mode.value,
        human_approved=(validated.target_mode == EnforcementMode.ENFORCED),
        change_receipt_id=receipt,
        next_step=f"Monitor VPC-SC Cloud Audit Logs for '{validated.perimeter_name}' over the next 24h.",
    ).model_dump()


# ADK FunctionTool wrapper enforcing interactive HITL confirmation in ADK Runner / Web UI
enforce_vpc_sc_hitl_tool = FunctionTool(
    func=enforce_vpc_sc_perimeter_policy,
    require_confirmation=True,
)
