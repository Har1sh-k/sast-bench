"""Agent router — dispatches plan steps to the appropriate tool."""

from agent.planner import PlanStep
from tools.command_runner import run_command


def execute_plan(plan: list[PlanStep]) -> list[dict]:
    """Execute each step in the coding-agent plan and collect results."""
    results: list[dict] = []

    for step in plan:
        if step["action"] == "run_command":
            result = run_command(step["command"])
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
            results.append(
                {
                    "command": step.get("command", ""),
                    "allowed": False,
                    "return_code": None,
                    "stdout": "",
                    "stderr": "",
                    "errors": [f"Unknown action: {step['action']}"],
                }
            )

    return results
