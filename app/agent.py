"""Multi-Agent Orchestration (Coordinator, Parallel, Loop, Sequential) & Strategic Model Routing."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

from app.guardrails import (
    ArbSecurityGuardrailPlugin,
    default_guardrail_plugin,
    default_self_evaluator,
)
from app.memory import (
    AsyncMemoryConsolidator,
    ConversationTurn,
    PersistentSessionStore,
    async_after_agent_memory_callback,
    build_context_cache_config,
    build_events_compaction_config,
    default_async_memory,
    default_session_store,
    get_memory_retrieval_tools,
)
from app.observability import log_agent_intent_before_callback, tracer
from app.prompts import (
    AGENT_CONSTITUTION,
    BLUE_TEAM_ARCHITECT_INSTRUCTION,
    CONTROL_CATALOG_INSTRUCTION,
    RED_TEAM_ADVERSARY_INSTRUCTION,
    SELF_EVAL_CRITIC_INSTRUCTION,
    TOPOLOGY_INSPECTOR_INSTRUCTION,
)
from app.tools import (
    enforce_vpc_sc_hitl_tool,
    enforce_vpc_sc_perimeter_policy,
    inspect_landing_zone_topology,
    record_architecture_risk_finding,
    search_security_control_catalog,
    simulate_exfiltration_attack_path,
)

try:
    from google.adk.agents import Agent, LoopAgent, ParallelAgent, SequentialAgent
    from google.adk.apps import App
    from google.adk.apps.app import ResumabilityConfig
    from google.adk.models import Gemini
    HAS_GOOGLE_ADK = True
except ImportError:  # pragma: no cover - lightweight shims for bare-Python unit/eval runs
    HAS_GOOGLE_ADK = False

    class Gemini:  # type: ignore[no-redef]
        def __init__(self, model: str) -> None:
            self.model = model

    class Agent:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    class ParallelAgent(Agent):  # type: ignore[no-redef]
        pass

    class LoopAgent(Agent):  # type: ignore[no-redef]
        pass

    class SequentialAgent(Agent):  # type: ignore[no-redef]
        pass

    @dataclass
    class ResumabilityConfig:  # type: ignore[no-redef]
        is_resumable: bool = True

    class App:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)


# Strategic Model Routing tiers
FAST_TRIAGE_MODEL = os.environ.get("FAST_TRIAGE_MODEL", "gemini-2.5-flash")
DEEP_REASONING_MODEL = os.environ.get("DEEP_REASONING_MODEL", "gemini-2.5-pro")


@dataclass(frozen=True)
class ModelRouteDecision:
    """Explicit routing telemetry emitted by `StrategicModelRouter`."""

    task_type: str
    selected_model: str
    tier: str
    rationale: str


class StrategicModelRouter:
    """Routes fast recon/catalog tasks to Gemini Flash and deep Red/Blue planning to Gemini Pro."""

    _FAST_TASKS = frozenset({"topology_recon", "control_lookup", "quick_triage"})

    def route(self, task_type: str) -> ModelRouteDecision:
        if task_type in self._FAST_TASKS:
            return ModelRouteDecision(
                task_type=task_type,
                selected_model=FAST_TRIAGE_MODEL,
                tier="fast",
                rationale="Low-latency structured inspection and catalog retrieval routed to Gemini Flash.",
            )
        return ModelRouteDecision(
            task_type=task_type,
            selected_model=DEEP_REASONING_MODEL,
            tier="deep_reasoning",
            rationale="Adversarial Red-Team simulation, Zero-Trust defense synthesis, and critique routed to Gemini Pro.",
        )

    def build_model(self, task_type: str) -> Gemini:
        return Gemini(model=self.route(task_type).selected_model)


model_router = StrategicModelRouter()

# 1. Parallel Recon Sub-Agents (Gemini Flash)
topology_inspector_agent = Agent(
    name="topology_inspector_agent",
    description="Fast recon agent inspecting NCC spokes, VPC-SC mode, PSC, and egress exposure.",
    model=model_router.build_model("topology_recon"),
    instruction=TOPOLOGY_INSPECTOR_INSTRUCTION,
    tools=[inspect_landing_zone_topology],
    output_key="topology_report",
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

control_catalog_agent = Agent(
    name="control_catalog_agent",
    description="Fast retrieval agent querying CIS GCP, Zero-Trust, and VPC-SC control catalogs.",
    model=model_router.build_model("control_lookup"),
    instruction=CONTROL_CATALOG_INSTRUCTION,
    tools=[search_security_control_catalog],
    output_key="control_catalog_report",
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

parallel_recon_gatherers = ParallelAgent(
    name="parallel_recon_gatherers",
    description="Concurrently gathers Landing Zone topology state and Zero-Trust control guidance.",
    sub_agents=[topology_inspector_agent, control_catalog_agent],
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

# 2. Adversarial Red-Team vs. Blue-Team & Constitutional Critic Loop (Gemini Pro)
red_team_adversary_agent = Agent(
    name="red_team_adversary_agent",
    description="Adversarial Red-Team agent simulating exfiltration and lateral movement kill chains.",
    model=model_router.build_model("red_team_simulation"),
    instruction=RED_TEAM_ADVERSARY_INSTRUCTION,
    tools=[simulate_exfiltration_attack_path],
    output_key="red_team_report",
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

blue_team_architect_agent = Agent(
    name="blue_team_architect_agent",
    description="Blue-Team architect recording ARB findings and proposing HITL-gated VPC-SC enforcement.",
    model=model_router.build_model("blue_team_planning"),
    instruction=BLUE_TEAM_ARCHITECT_INSTRUCTION,
    tools=[record_architecture_risk_finding, enforce_vpc_sc_hitl_tool],
    output_key="blue_team_plan",
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

constitutional_critic_agent = Agent(
    name="constitutional_critic_agent",
    description="Self-evaluation critic verifying groundedness, HITL compliance, and zero PII leakage.",
    model=model_router.build_model("constitutional_critique"),
    instruction=SELF_EVAL_CRITIC_INSTRUCTION,
    output_key="verified_arb_verdict",
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

red_blue_war_game_loop = LoopAgent(
    name="red_blue_war_game_loop",
    description="Iterative Red-Team attack simulation, Blue-Team defense design, and constitutional critique.",
    sub_agents=[red_team_adversary_agent, blue_team_architect_agent, constitutional_critic_agent],
    max_iterations=1,
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

# 3. End-to-End Sequential Pipeline
architecture_review_pipeline = SequentialAgent(
    name="architecture_review_pipeline",
    description="Sequential PSO Architecture Review pipeline: parallel recon -> Red/Blue war-game -> critic.",
    sub_agents=[parallel_recon_gatherers, red_blue_war_game_loop],
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

# 4. Root Coordinator Agent exported for `adk web` / `adk run` / `agents-cli`
root_agent = Agent(
    name="pso_arb_coordinator",
    description="Principal Cloud Security & Networking Architect coordinating the PSO Architecture Review Board.",
    model=model_router.build_model("coordinator"),
    instruction=AGENT_CONSTITUTION,
    tools=[*get_memory_retrieval_tools()],
    sub_agents=[architecture_review_pipeline],
    before_agent_callback=log_agent_intent_before_callback,
    after_agent_callback=async_after_agent_memory_callback,
)

# ADK Application (`name="app"` matches directory name per ADK convention)
app = App(
    name="app",
    root_agent=root_agent,
    events_compaction_config=build_events_compaction_config(summarizer_model=FAST_TRIAGE_MODEL),
    context_cache_config=build_context_cache_config(),
    resumability_config=ResumabilityConfig(is_resumable=True),
    plugins=[ArbSecurityGuardrailPlugin()],
)


class ArchitectureReviewOrchestrator:
    """Deterministic async orchestrator exercising the full multi-agent pipeline for local & eval runs."""

    def __init__(
        self,
        session_store: PersistentSessionStore = default_session_store,
        async_memory: AsyncMemoryConsolidator = default_async_memory,
        guardrail: ArbSecurityGuardrailPlugin = default_guardrail_plugin,
    ) -> None:
        self.session_store = session_store
        self.async_memory = async_memory
        self.guardrail = guardrail

    async def run_review(
        self,
        *,
        session_id: str,
        user_query: str,
        blueprint_id: str,
        environment: str = "prod",
        threat_vector: str = "data_exfiltration",
        request_enforcement: bool = False,
        human_approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Run Coordinator -> Parallel Recon -> Red/Blue War-Game -> HITL Enforcement -> Self-Eval -> Async Memory."""
        with tracer.start_span("request.architecture_review", {"session.id": session_id, "blueprint.id": blueprint_id}):
            # 1. Input Security Guardrail
            blocked = self.guardrail.inspect_prompt_security(user_query)
            if blocked is not None:
                return {"status": "blocked_by_guardrail", "session_id": session_id, "guardrail_decision": blocked}

            # 2. Persist pinned constitution + user turn
            if not self.session_store.get_turns(session_id):
                self.session_store.append_turn(session_id, ConversationTurn(role="system", content=AGENT_CONSTITUTION[:320], pinned=True))
            self.session_store.append_turn(session_id, ConversationTurn(role="user", content=user_query))

            # 3. Parallel Recon (Gemini Flash)
            recon_route = model_router.route("topology_recon")
            with tracer.start_span("agent.parallel_recon_gatherers", {"model": recon_route.selected_model}):
                topology, controls = await asyncio.gather(
                    asyncio.to_thread(inspect_landing_zone_topology, blueprint_id=blueprint_id, environment=environment),
                    asyncio.to_thread(search_security_control_catalog, risk_query=f"{blueprint_id} vpc-sc egress", framework="vpc-sc"),
                )
            if topology.get("status") == "error":
                return {"status": "guided_error", "session_id": session_id, "topology": topology}

            # 4. Red-Team Simulation (Gemini Pro)
            pro_route = model_router.route("red_team_simulation")
            with tracer.start_span("agent.red_team_adversary", {"model": pro_route.selected_model}):
                attack = simulate_exfiltration_attack_path(blueprint_id=blueprint_id, threat_vector=threat_vector)

            # 5. Blue-Team Finding & Optional HITL-Gated VPC-SC Enforcement (Gemini Pro)
            finding: dict[str, Any] | None = None
            enforcement: dict[str, Any] | None = None
            with tracer.start_span("agent.blue_team_architect", {"model": pro_route.selected_model}):
                if attack.get("exploit_viable"):
                    primary_ctl = (attack.get("recommended_control_ids") or ["CTL-VPCSC-01"])[0]
                    finding = record_architecture_risk_finding(
                        blueprint_id=blueprint_id,
                        severity="CRITICAL" if attack["blast_radius_score"] >= 75 else "HIGH",
                        title=f"{blueprint_id} vulnerable to {threat_vector} (VPC-SC {topology['vpc_sc_mode']})",
                        control_id=primary_ctl,
                        remediation_summary="Restrict spoke internet egress and promote VPC-SC perimeter to enforced mode.",
                    )
                    if request_enforcement:
                        enforcement = enforce_vpc_sc_perimeter_policy(
                            blueprint_id=blueprint_id,
                            perimeter_name=f"{blueprint_id.replace('-', '_')}_perimeter",
                            target_mode="enforced",
                            finding_id=finding["finding_id"],
                            blast_radius_justification="Dry-run audit logs reviewed; ingress/egress allowlists verified.",
                            human_approval_token=human_approval_token,
                        )

            # 6. Constitutional Self-Evaluation Critic
            control_ids = ", ".join(attack.get("recommended_control_ids", []))
            enf_status = enforcement["status"] if enforcement else "not_requested"
            draft = (
                f"ARB Verdict for {blueprint_id}: Posture={topology['posture_grade']}, "
                f"Blast Radius={attack['blast_radius_score']}/100, Controls=[{control_ids}], "
                f"Finding={finding['finding_id'] if finding else 'NONE'}, "
                f"VPC-SC Enforcement={enf_status}."
            )
            self_eval = default_self_evaluator.evaluate_response(
                draft_response=draft,
                evidence_records=[topology, controls, attack],
                requires_hitl_notice=(enf_status == "pending_human_approval"),
            )

            # 7. Persist compacted assistant turn + fire non-blocking async background memory task
            turns = self.session_store.append_turn(session_id, ConversationTurn(role="assistant", content=self_eval.sanitized_response))
            bg_task = self.async_memory.schedule_background_consolidation(session_id, turns)

            return {
                "status": "success",
                "session_id": session_id,
                "models_used": {"recon": recon_route.selected_model, "war_game": pro_route.selected_model},
                "topology": topology,
                "controls": controls,
                "attack_simulation": attack,
                "finding": finding,
                "enforcement": enforcement,
                "self_evaluation": {
                    "passed": self_eval.passed,
                    "overall_score": self_eval.overall_score,
                    "groundedness_score": self_eval.groundedness_score,
                    "safety_score": self_eval.safety_score,
                },
                "verdict": self_eval.sanitized_response,
                "background_memory_scheduled": bg_task is not None,
            }


default_orchestrator = ArchitectureReviewOrchestrator()
