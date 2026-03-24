"""Task Assistant Agent — main entrypoint.

Accepts a user message describing tasks, parses them via the planner,
and dispatches them through the router to the task executor tool.
"""

from __future__ import annotations

import logging
import sys

from agent.planner import parse_tasks
from agent.router import dispatch_tasks

logger = logging.getLogger(__name__)


def main(user_message: str) -> None:
    """Run a user message through the task assistant pipeline."""
    try:
        tasks = parse_tasks(user_message)
        results = dispatch_tasks(tasks)
    except Exception:
        logger.exception("Fatal error during task execution")
        sys.exit(2)

    for result in results:
        status = result.get("status", "unknown")
        name = result.get("name", "")
        message = result.get("message", "")
        print(f"[{status}] {name}: {message}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <user_message>")
        sys.exit(1)
    main(sys.argv[1])
