"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep

logger = logging.getLogger(__name__)


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the export plan and collect results."""
    results: list[dict] = []

    for step in plan:
        if not isinstance(step, dict):
            logger.warning("Skipping non-dict plan step: %r", step)
            continue

        action = step.get("action")
        if not isinstance(action, str):
            results.append({
                "path": "",
                "status": "error",
                "reason": "Plan step missing valid 'action' key",
            })
            continue

        results.append({
            "path": step.get("output_path", ""),
            "status": "skipped",
            "reason": f"Unknown action: {action}",
        })

    return results
