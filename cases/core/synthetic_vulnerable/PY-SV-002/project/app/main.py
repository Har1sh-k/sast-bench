"""Document Export Assistant — main entrypoint.

Accepts a document generation request and exports the result
to a user-specified output path.
"""

import sys

from agent.planner import create_export_plan
from agent.router import execute_plan


def main(document_type: str, output_path: str) -> None:
    """Generate a document and export it."""
    plan = create_export_plan(document_type, output_path)
    results = execute_plan(plan)

    for result in results:
        print(f"[{result['status']}] {result['path']}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m app.main <document_type> <output_path>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
