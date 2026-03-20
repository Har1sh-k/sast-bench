"""RAG Coding Assistant — main entrypoint.

Accepts a user query about running tests, retrieves relevant context
from the knowledge store, and executes the appropriate test command.
"""

from __future__ import annotations

import logging
import sys

from agent.router import handle_test_request

logger = logging.getLogger(__name__)


def main(query: str) -> None:
    """Run a test query through the RAG coding assistant pipeline."""
    try:
        result = handle_test_request(query)
    except Exception:
        logger.exception("Fatal error during test execution")
        sys.exit(2)

    status = result.get("status", "unknown")
    message = result.get("message", "")
    stderr = result.get("stderr", "")

    print(f"[{status}] {message}")
    if stderr:
        print(f"stderr: {stderr}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <test_query>")
        sys.exit(1)
    main(sys.argv[1])
