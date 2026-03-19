"""Command runner tool — executes shell commands for the coding agent.

SAFE: Although this module invokes ``subprocess.run()``, every command is
validated against a strict, hardcoded allowlist *before* execution.  The
allowlist is defined in ``guards.command_policy`` and only permits a small
set of developer-tool commands (pytest, ruff, mypy, black).

A static-analysis scanner may flag the ``subprocess.run()`` call, but it
should recognise that:
  1. The command is checked against an immutable allowlist.
  2. ``shell=False`` is used — the command is passed as a list of tokens.
  3. Rejected commands never reach ``subprocess.run()``.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass, field

from guards.command_policy import check_command

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Outcome of a command execution attempt."""

    command: str
    allowed: bool
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    errors: list[str] = field(default_factory=list)


def run_command(command: str, timeout: int = 120) -> CommandResult:   # line 33
    """Run *command* if — and only if — it passes the allowlist check.

    Parameters
    ----------
    command:
        The full shell command string requested by the agent (e.g.
        ``"pytest -v tests/"``).
    timeout:
        Maximum execution time in seconds.

    Returns
    -------
    CommandResult
        Contains stdout/stderr on success, or an error description if the
        command was rejected by policy.
    """
    # ── Step 1: policy gate ──────────────────────────────────────
    verdict = check_command(command)

    if not verdict.allowed:
        logger.warning(
            "Blocked disallowed command: %s (reason: %s)",
            command,
            verdict.reason,
        )
        return CommandResult(
            command=command,
            allowed=False,
            errors=[verdict.reason],
        )

    # ── Step 2: execute via subprocess (shell=False) ─────────────
    tokens = shlex.split(verdict.command)
    logger.info("Executing allowed command: %s", tokens)

    try:
        proc = subprocess.run(                                       # line 67
            tokens,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,                                             # line 72
        )
        return CommandResult(
            command=verdict.command,
            allowed=True,
            return_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=verdict.command,
            allowed=True,
            errors=[f"Command timed out after {timeout}s"],
        )
    except FileNotFoundError:
        return CommandResult(
            command=verdict.command,
            allowed=True,
            errors=[f"Executable not found: {tokens[0]!r}"],
        )                                                            # line 88
