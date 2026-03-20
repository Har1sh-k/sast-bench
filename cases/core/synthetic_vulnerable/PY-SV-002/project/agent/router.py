"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep
from tools.file_writer import write_document

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

        if action == "write_file":
            content = step.get("content")
            output_path = step.get("output_path")
            if not isinstance(content, str) or not isinstance(output_path, str):
                results.append({
                    "path": output_path or "",
                    "status": "error",
                    "reason": "write_file step missing valid 'content' or 'output_path'",
                })
                continue
            try:
                result = write_document(content, output_path)
            except Exception as exc:
                logger.exception("Unhandled error writing %s", output_path)
                result = {"path": output_path, "status": "error", "reason": str(exc)}
            results.append(result)
        else:
            results.append({
                "path": step.get("output_path", ""),
                "status": "skipped",
            })

    return results
