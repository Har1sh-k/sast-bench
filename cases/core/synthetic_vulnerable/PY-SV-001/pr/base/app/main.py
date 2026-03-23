"""Medical Research Agent — main entrypoint.

Accepts a research query, runs the planner to identify references,
and fetches them via the reference fetcher tool.
"""

from __future__ import annotations

import logging
import sys

from agent.planner import create_research_plan
from agent.router import execute_plan

logger = logging.getLogger(__name__)


def main(query: str) -> None:
    """Run a research query end-to-end."""
    try:
        plan = create_research_plan(query)
        results = execute_plan(plan)
    except Exception:
        logger.exception("Fatal error during research plan execution")
        sys.exit(2)

    for result in results:
        status = result.get("status", "unknown")
        url = result.get("url", "")
        title = result.get("title", "")
        print(f"[{status}] {url}: {title}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <research_query>")
        sys.exit(1)
    main(sys.argv[1])
