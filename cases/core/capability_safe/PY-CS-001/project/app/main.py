"""Coding Agent — main entrypoint.

Accepts a task description, runs the planner to decide which dev-tool
commands to execute, and dispatches them through the command runner.
"""

import sys

from agent.planner import create_plan
from agent.router import execute_plan


def main(task: str) -> None:
    """Run a coding-agent task end-to-end."""
    plan = create_plan(task)
    results = execute_plan(plan)

    for result in results:
        status = "ALLOWED" if result["allowed"] else "BLOCKED"
        print(f"[{status}] {result['command']}")
        if result["errors"]:
            for err in result["errors"]:
                print(f"         error: {err}")
        elif result["stdout"]:
            for line in result["stdout"].splitlines()[:5]:
                print(f"         {line}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <task_description>")
        sys.exit(1)
    main(sys.argv[1])
