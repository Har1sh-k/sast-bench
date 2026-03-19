"""Medical Triage Assistant — main entrypoint.

Accepts a symptom description, runs the triage planner to build an
action plan, then executes the plan via the agent router.
"""

import sys

from agent.planner import create_triage_plan
from agent.router import execute_plan


def main(symptoms: str) -> None:
    """Run a triage query end-to-end."""
    plan = create_triage_plan(symptoms)
    results = execute_plan(plan)

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
