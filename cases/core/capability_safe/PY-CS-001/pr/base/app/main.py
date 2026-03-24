"""Coding Agent — main entrypoint.

Accepts a task description, runs the planner to decide which dev-tool
commands to execute, and dispatches them through the command runner.
"""

from __future__ import annotations

import logging
import sys

from agent.planner import create_plan
from agent.router import execute_plan

logger = logging.getLogger(__name__)


def main(task: str) -> None:
    """Run a coding-agent task end-to-end."""
    try:
        plan = create_plan(task)
        results = execute_plan(plan)
    except Exception:
        logger.exception("Fatal error during coding-agent plan execution")
        sys.exit(2)

    for result in results:
        status = "ALLOWED" if result.get("allowed") else "BLOCKED"
        command = result.get("command", "")
        print(f"[{status}] {command}")
        errors = result.get("errors", [])
        if errors:
            for err in errors:
                print(f"         error: {err}")
        elif result.get("stdout"):
            for line in result["stdout"].splitlines()[:5]:
                print(f"         {line}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <task_description>")
        sys.exit(1)
    main(sys.argv[1])
