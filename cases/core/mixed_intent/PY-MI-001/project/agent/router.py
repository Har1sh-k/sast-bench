"""Agent router — dispatches plan steps to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import PlanStep
from tools.clinical_fetcher import fetch_clinical_data
from tools.preview_fetcher import fetch_preview

logger = logging.getLogger(__name__)


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the triage plan and collect results.

    Routing logic:
    - ``fetch_clinical`` -> :func:`tools.clinical_fetcher.fetch_clinical_data`
      (guarded by host allowlist)
    - ``fetch_preview``  -> :func:`tools.preview_fetcher.fetch_preview`
      (no host restriction -- vulnerable to SSRF)
    """
    results: list[dict] = []

    for step in plan:
        if not isinstance(step, dict):
            logger.warning("Skipping non-dict plan step: %r", step)
            continue

        action = step.get("action")
        if not isinstance(action, str):
            results.append({
                "url": "",
                "status": "error",
                "snippet": "Plan step missing valid 'action' key",
            })
            continue

        url = step.get("url")
        if not isinstance(url, str) or not url:
            results.append({
                "url": "",
                "status": "error",
                "snippet": f"Step '{action}' missing valid 'url'",
            })
            continue

        if action == "fetch_clinical":
            try:
                result = fetch_clinical_data(url)
            except Exception as exc:
                logger.exception("Unhandled error in clinical fetch: %s", url)
                result = {"url": url, "status": "error", "snippet": str(exc)}
            results.append(result)

        elif action == "fetch_preview":
            try:
                result = fetch_preview(url)
            except Exception as exc:
                logger.exception("Unhandled error in preview fetch: %s", url)
                result = {"url": url, "status": "error", "snippet": str(exc)}
            results.append(result)

        else:
            results.append({
                "url": url,
                "status": "skipped",
                "snippet": f"Unknown action: {action}",
            })

    return results
