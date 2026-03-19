"""File writer tool — writes content to an output path.

VULNERABLE: This tool joins a user-provided filename with a base directory
but does not validate that the resolved path stays within the workspace.
"""

import os

WORKSPACE_DIR = os.environ.get("AGENT_WORKSPACE", "/tmp/agent-workspace")
OUTPUT_DIR = os.path.join(WORKSPACE_DIR, "exports")


def write_document(content: str, output_path: str) -> dict:    # line 12
    """Write document content to the specified output path.

    The output_path comes from user input via the agent planner.
    It is joined with OUTPUT_DIR using os.path.join, but there is
    no check that the resolved path remains under OUTPUT_DIR.

    os.path.join has a known behavior: if the second argument is an
    absolute path, it discards the first argument entirely.
    Even for relative paths, sequences like '../../' can escape
    the intended directory.

    A proper guard would resolve the path with os.path.realpath()
    and verify it starts with the workspace root prefix.
    """
    full_path = os.path.join(OUTPUT_DIR, output_path)           # line 28

    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    with open(full_path, "w") as f:                             # line 31
        f.write(content)

    return {
        "path": full_path,
        "status": "ok",
    }                                                           # line 35
