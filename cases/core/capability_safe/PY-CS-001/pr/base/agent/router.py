"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep

logger = logging.getLogger(__name__)


def _skipped_result(command: str, reason: str) -> dict:
    return {
        "command": command,
        "allowed": False,
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "errors": [reason],
    }


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the coding-agent plan and collect results."""
    results: list[dict] = []

    for step in plan:
        if not isinstance(step, dict):
            logger.warning("Skipping non-dict plan step: %r", step)
            continue

        action = step.get("action")
        if not isinstance(action, str):
            results.append(_skipped_result("", "Plan step missing valid 'action' key"))
            continue

        # No tool implementations available yet — skip all actions.
        results.append(_skipped_result(
            step.get("command", ""),
            f"No handler registered for action: {action}",
        ))

    return results
