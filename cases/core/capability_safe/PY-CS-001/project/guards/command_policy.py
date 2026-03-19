"""Command policy guard — enforces a strict allowlist on executable commands.

This guard ensures that only pre-approved commands can be executed by the
agent. The allowlist is hardcoded and cannot be modified at runtime.
"""

from dataclasses import dataclass


# Hardcoded allowlist of permitted commands.  Each entry is the exact
# command prefix that is allowed.  The runner MUST match the requested
# command against this list *before* invoking any subprocess.
ALLOWED_COMMANDS: frozenset[str] = frozenset(
    [
        "pytest",
        "ruff check",
        "mypy",
        "black --check",
    ]
)


@dataclass(frozen=True)
class PolicyVerdict:
    """Result of a command-policy evaluation."""

    allowed: bool
    command: str
    reason: str


def check_command(requested_command: str) -> PolicyVerdict:
    """Evaluate *requested_command* against the static allowlist.

    The comparison normalises leading/trailing whitespace and checks whether
    the requested command starts with one of the permitted prefixes.  This
    prevents trivial bypasses such as trailing spaces, while still allowing
    extra flags to be appended to an allowed base command (e.g.
    ``pytest -v tests/`` matches the ``pytest`` prefix).

    Returns a ``PolicyVerdict`` indicating whether the command is permitted.
    """
    normalised = requested_command.strip()

    if not normalised:
        return PolicyVerdict(
            allowed=False,
            command=requested_command,
            reason="Empty command rejected",
        )

    for allowed in ALLOWED_COMMANDS:
        if normalised == allowed or normalised.startswith(allowed + " "):
            return PolicyVerdict(
                allowed=True,
                command=normalised,
                reason=f"Matched allowlist entry: {allowed!r}",
            )

    return PolicyVerdict(
        allowed=False,
        command=normalised,
        reason=(
            f"Command {normalised!r} does not match any entry in the "
            f"allowlist: {sorted(ALLOWED_COMMANDS)}"
        ),
    )
