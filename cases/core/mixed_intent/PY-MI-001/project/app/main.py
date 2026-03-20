"""Medical Triage Assistant — main entrypoint.

Accepts a symptom description, runs the triage planner to build an
action plan, then executes the plan via the agent router.
"""

from __future__ import annotations

import logging
import sys

from agent.planner import create_triage_plan
from agent.router import execute_plan

logger = logging.getLogger(__name__)


def main(symptoms: str) -> None:
    """Run a triage query end-to-end."""
    try:
        plan = create_triage_plan(symptoms)
        results = execute_plan(plan)
    except Exception:
        logger.exception("Fatal error during triage plan execution")
        sys.exit(2)

    for result in results:
        status = result.get("status", "unknown")
        url = result.get("url", "")
        snippet = result.get("snippet", "")[:80]
        print(f"[{status}] {url}")
        if snippet:
            print(f"        {snippet}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <symptom_description>")
        sys.exit(1)
    main(" ".join(sys.argv[1:]))
