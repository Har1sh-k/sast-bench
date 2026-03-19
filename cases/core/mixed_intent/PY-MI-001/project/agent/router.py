"""Agent router — dispatches plan steps to the appropriate tool."""

from agent.planner import PlanStep
from tools.clinical_fetcher import fetch_clinical_data
from tools.preview_fetcher import fetch_preview


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the triage plan and collect results.

    Routing logic:
    - ``fetch_clinical`` → :func:`tools.clinical_fetcher.fetch_clinical_data`
      (guarded by host allowlist)
    - ``fetch_preview``  → :func:`tools.preview_fetcher.fetch_preview`
      (no host restriction — vulnerable to SSRF)
    """
    results: list[dict] = []

    for step in plan:
        action = step["action"]

        if action == "fetch_clinical":
            result = fetch_clinical_data(step["url"])
            results.append(result)

        elif action == "fetch_preview":
            result = fetch_preview(step["url"])
            results.append(result)

        else:
            results.append({
                "url": step.get("url", ""),
                "status": "skipped",
                "snippet": f"Unknown action: {action}",
            })

    return results
