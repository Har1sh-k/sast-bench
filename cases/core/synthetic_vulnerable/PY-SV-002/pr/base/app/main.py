"""Document Export Assistant — main entrypoint.

Accepts a document generation request and exports the result
to a user-specified output path.
"""

from __future__ import annotations

import logging
import sys

from agent.planner import create_export_plan
from agent.router import execute_plan

logger = logging.getLogger(__name__)


def main(document_type: str, output_path: str) -> None:
    """Generate a document and export it."""
    try:
        plan = create_export_plan(document_type, output_path)
        results = execute_plan(plan)
    except Exception:
        logger.exception("Fatal error during export plan execution")
        sys.exit(2)

    for result in results:
        status = result.get("status", "unknown")
        path = result.get("path", "")
        print(f"[{status}] {path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m app.main <document_type> <output_path>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
