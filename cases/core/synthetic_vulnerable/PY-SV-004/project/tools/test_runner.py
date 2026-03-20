"""Test runner tool — executes test commands built from retrieved context.

VULNERABLE: This tool receives context snippets retrieved from the
knowledge store and string-interpolates them directly into a shell
command template passed to subprocess.run with shell=True. An attacker
who poisoned the knowledge store can inject shell metacharacters via
the retrieved snippets to execute arbitrary commands.
"""

from __future__ import annotations

import logging
import subprocess

from config.settings import TEST_TIMEOUT, WORKSPACE_DIR

logger = logging.getLogger(__name__)

MAX_COMMAND_LENGTH = 4096


def run_tests(context_snippets: list[str]) -> dict:             # line 22
    """Build and execute a test command from retrieved context snippets.

    The ``context_snippets`` originate from the knowledge store, which
    may contain entries written by untrusted parties. The snippets are
    concatenated and interpolated directly into a shell command string.

    Using ``shlex.quote()`` on each snippet — or using an explicit argv
    list without shell=True — would prevent command injection here but
    is missing.
    """
    # Concatenate all retrieved context into a single instruction string.
    # This string is then interpolated into the shell command template.
    combined_context = " && ".join(context_snippets)

    # Build the shell command from the retrieved context.
    # The context content is interpolated without any escaping, so
    # shell metacharacters (;, |, $(), &&, etc.) embedded in the
    # knowledge store entries will be interpreted by the shell.
    cmd = f'cd {WORKSPACE_DIR} && echo "Running tests per context..." && {combined_context}'

    if len(cmd) > MAX_COMMAND_LENGTH:
        return {
            "status": "error",
            "message": f"Constructed command exceeds {MAX_COMMAND_LENGTH} char limit",
        }

    try:
        result = subprocess.run(                                # line 50
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT,
            cwd=WORKSPACE_DIR,
        )

        return {                                                # line 59
            "status": "ok" if result.returncode == 0 else "error",
            "message": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Test execution timed out after {TEST_TIMEOUT}s",
        }
    except OSError as exc:
        return {
            "status": "error",
            "message": f"Failed to execute test command: {exc}",
        }
