"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep

logger = logging.getLogger(__name__)


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the research plan and collect results."""
    results: list[dict] = []

    for step in plan:
        if not isinstance(step, dict):
            logger.warning("Skipping non-dict plan step: %r", step)
            continue

        action = step.get("action")
        if not isinstance(action, str):
            logger.warning("Skipping step with missing/invalid 'action': %r", step)
            results.append({
                "url": "",
                "status": "error",
                "title": "Plan step missing valid 'action' key",
            })
            continue

        results.append({
            "url": step.get("url", ""),
            "status": "skipped",
            "title": f"Unknown action: {action}",
        })

    return results
