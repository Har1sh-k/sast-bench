"""Medical Research Agent — main entrypoint.

Accepts a research query, runs the planner to identify references,
and fetches them via the reference fetcher tool.
"""

import sys

from agent.planner import create_research_plan
from agent.router import execute_plan


def main(query: str) -> None:
    """Run a research query end-to-end."""
    plan = create_research_plan(query)
    results = execute_plan(plan)

    for result in results:
        print(f"[{result['status']}] {result['url']}: {result['title']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <research_query>")
        sys.exit(1)
    main(sys.argv[1])
