"""Task executor tool — runs shell commands for task operations.

VULNERABLE: This tool constructs shell commands by string-formatting
user-supplied task descriptions directly into a command template and
passes them to subprocess.run with shell=True. An attacker can inject
shell metacharacters in the task description to execute arbitrary
commands.
"""

from __future__ import annotations

import logging
import subprocess

from config.settings import TASK_TIMEOUT, WORKSPACE_DIR

logger = logging.getLogger(__name__)


def execute_task(name: str, description: str) -> dict:          # line 20
    """Execute a task by logging it via a shell command.

    The ``description`` parameter originates from user input and is
    passed through the planner and router without sanitisation. It is
    string-interpolated directly into a shell command template.

    Using ``shlex.quote()`` on the description — or avoiding shell=True
    entirely by passing an explicit argv list — would prevent command
    injection here but is missing.
    """
    try:
        # Build a shell command that logs the task description.
        # The description is interpolated without any escaping, so
        # shell metacharacters (;, |, $(), &&, etc.) in the user
        # input will be interpreted by the shell.
        cmd = f'echo "Executing task: {description}" | tee -a {WORKSPACE_DIR}/tasks.log'

        result = subprocess.run(                                # line 38
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TASK_TIMEOUT,
            cwd=WORKSPACE_DIR,
        )

        if result.returncode != 0:
            return {
                "name": name,
                "status": "error",
                "message": f"Command exited with code {result.returncode}: {result.stderr}",
            }                                                   # line 50

        return {
            "name": name,
            "status": "ok",
            "message": result.stdout.strip(),
        }
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "status": "error",
            "message": f"Task timed out after {TASK_TIMEOUT}s",
        }
    except OSError as exc:
        return {
            "name": name,
            "status": "error",
            "message": f"Failed to execute command: {exc}",
        }
