"""Agent router — dispatches plan steps to the appropriate tool."""

from agent.planner import PlanStep
from tools.file_writer import write_document


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the export plan and collect results."""
    results = []

    for step in plan:
        if step["action"] == "write_file":
            result = write_document(step["content"], step["output_path"])
            results.append(result)
        else:
            results.append({
                "path": step.get("output_path", ""),
                "status": "skipped",
            })

    return results
