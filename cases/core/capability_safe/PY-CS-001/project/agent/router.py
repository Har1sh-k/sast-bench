"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep
from tools.command_runner import run_command

logger = logging.getLogger(__name__)


def _error_result(command: str, reason: str) -> dict:
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
            results.append(_error_result("", "Plan step missing valid 'action' key"))
            continue

        if action == "run_command":
            command = step.get("command")
            if not isinstance(command, str) or not command:
                results.append(_error_result("", "run_command step missing valid 'command'"))
                continue
            result = run_command(command)
            results.append(
                {
                    "command": result.command,
                    "allowed": result.allowed,
                    "return_code": result.return_code,
                    "stdout": result.stdout[:500] if result.stdout else "",
                    "stderr": result.stderr[:500] if result.stderr else "",
                    "errors": result.errors,
                }
            )
        else:
            results.append(_error_result(
                step.get("command", ""),
                f"Unknown action: {action}",
            ))

    return results
