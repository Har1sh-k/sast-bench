"""Agent router — dispatches plan steps to the appropriate tool."""

from agent.planner import PlanStep
from tools.reference_fetcher import fetch_reference


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the research plan and collect results."""
    results = []

    for step in plan:
        if step["action"] == "fetch_reference":
            result = fetch_reference(step["url"])
            results.append(result)
        else:
            results.append({
                "url": step.get("url", ""),
                "status": "skipped",
                "title": f"Unknown action: {step['action']}",
            })

    return results
