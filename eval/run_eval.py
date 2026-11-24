"""Automated Golden-Dataset Evaluation & Regression Harness."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agent import ArchitectureReviewOrchestrator  # noqa: E402
from app.memory import AsyncMemoryConsolidator, HistoryCompactor, PersistentSessionStore  # noqa: E402
from app.observability import audit_logger, tracer  # noqa: E402

try:
    from google.adk.evaluation.agent_evaluator import AgentEvaluator
    HAS_ADK_EVALUATOR = True
except ImportError:  # pragma: no cover
    AgentEvaluator = None
    HAS_ADK_EVALUATOR = False


async def run_golden_evaluation(dataset_path: Path | None = None) -> dict[str, Any]:
    """Execute every scenario in `eval/golden_dataset.json` and assert zero regressions."""
    path = dataset_path or (ROOT / "eval" / "golden_dataset.json")
    cases: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))

    store = PersistentSessionStore(compactor=HistoryCompactor())
    orchestrator = ArchitectureReviewOrchestrator(
        session_store=store,
        async_memory=AsyncMemoryConsolidator(store),
    )

    results: list[dict[str, Any]] = []
    passed = 0

    for case in cases:
        audit_logger.clear()
        tracer.clear()

        res = await orchestrator.run_review(
            session_id=case["session_id"],
            user_query=case["user_query"],
            blueprint_id=case["blueprint_id"],
            environment=case.get("environment", "prod"),
            threat_vector=case.get("threat_vector", "data_exfiltration"),
            request_enforcement=case.get("request_enforcement", False),
            human_approval_token=case.get("human_approval_token"),
        )
        await orchestrator.async_memory.flush()

        status_ok = res.get("status") == case["expected_status"]
        if case["expected_status"] != "success":
            ok = status_ok
            results.append({"eval_id": case["eval_id"], "passed": ok, "status": res.get("status")})
            passed += int(ok)
            continue

        # Verify tool trajectory (first 2 tools run concurrently in ParallelAgent)
        trails = audit_logger.audit_trail()
        actual_tools = [r["tool_name"] for r in trails if r["event_phase"] == "INTENT" and r["tool_name"]]
        exp_tools = case["expected_tools"]
        traj_ok = (
            len(actual_tools) == len(exp_tools)
            and set(actual_tools[:2]) == set(exp_tools[:2])
            and actual_tools[2:] == exp_tools[2:]
        )

        posture_ok = res["topology"]["posture_grade"] == case["expected_posture"]
        exploit_ok = res["attack_simulation"]["exploit_viable"] == case["expected_exploit_viable"]
        eval_ok = res["self_evaluation"]["passed"] == case["expected_self_eval_passed"]
        enf_ok = True
        if "expected_enforcement_status" in case:
            enf_ok = (res.get("enforcement") or {}).get("status") == case["expected_enforcement_status"]

        serialized = json.dumps(trails) + json.dumps(tracer.recorded_spans()) + res.get("verdict", "")
        pii_ok = all(token not in serialized for token in case.get("forbidden_in_logs", []))

        ok = all((status_ok, traj_ok, posture_ok, exploit_ok, eval_ok, enf_ok, pii_ok))
        passed += int(ok)
        results.append(
            {
                "eval_id": case["eval_id"],
                "passed": ok,
                "trajectory_ok": traj_ok,
                "posture_ok": posture_ok,
                "exploit_ok": exploit_ok,
                "enforcement_ok": enf_ok,
                "self_eval_ok": eval_ok,
                "pii_ok": pii_ok,
            }
        )

    return {
        "suite": "pso_arb_golden_regression_suite",
        "total": len(cases),
        "passed": passed,
        "pass_rate": round(passed / max(1, len(cases)), 4),
        "adk_evaluator_available": HAS_ADK_EVALUATOR,
        "results": results,
    }


def main() -> int:
    summary = asyncio.run(run_golden_evaluation())
    audit_logger.log_outcome(
        correlation_id="golden-eval-run",
        action_type="EVAL_SUITE",
        target_name="run_golden_evaluation",
        actual_status="passed" if summary["pass_rate"] == 1.0 else "failed",
        actual_output=summary,
        duration_ms=10.0,
    )
    return 0 if summary["pass_rate"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
