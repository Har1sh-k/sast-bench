"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep
from tools.reference_fetcher import fetch_reference

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

        if action == "fetch_reference":
            url = step.get("url")
            if not isinstance(url, str) or not url:
                results.append({
                    "url": "",
                    "status": "error",
                    "title": "fetch_reference step missing valid 'url'",
                })
                continue
            try:
                result = fetch_reference(url)
            except Exception as exc:
                logger.exception("Unhandled error fetching %s", url)
                result = {
                    "url": url,
                    "status": "error",
                    "title": f"Internal error: {exc}",
                }
            results.append(result)
        else:
            results.append({
                "url": step.get("url", ""),
                "status": "skipped",
                "title": f"Unknown action: {action}",
            })

    return results
