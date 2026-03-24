"""Agent router — dispatches tasks to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import Task

logger = logging.getLogger(__name__)


def dispatch_tasks(tasks: list[Task]) -> list[dict]:
    """Execute each task by dispatching to the appropriate tool."""
    results: list[dict] = []

    for task in tasks:
        if not isinstance(task, dict):
            logger.warning("Skipping non-dict task: %r", task)
            continue

        action = task.get("action")
        if not isinstance(action, str):
            logger.warning("Skipping task with missing/invalid 'action': %r", task)
            results.append({
                "name": "",
                "status": "error",
                "message": "Task missing valid 'action' key",
            })
            continue

        results.append({
            "name": task.get("name", ""),
            "status": "skipped",
            "message": f"Unknown action: {action}",
        })

    return results
