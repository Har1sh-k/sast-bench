"""Agent router — dispatches tasks to the appropriate tool."""

from __future__ import annotations

import logging

from agent.planner import Task
from tools.task_executor import execute_task

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

        if action == "execute_task":
            name = task.get("name", "unnamed")
            description = task.get("description")
            if not isinstance(description, str) or not description:
                results.append({
                    "name": name,
                    "status": "error",
                    "message": "execute_task requires a non-empty 'description'",
                })
                continue
            try:
                result = execute_task(name, description)
            except Exception as exc:
                logger.exception("Unhandled error executing task %s", name)
                result = {
                    "name": name,
                    "status": "error",
                    "message": f"Internal error: {exc}",
                }
            results.append(result)
        else:
            results.append({
                "name": task.get("name", ""),
                "status": "skipped",
                "message": f"Unknown action: {action}",
            })

    return results
