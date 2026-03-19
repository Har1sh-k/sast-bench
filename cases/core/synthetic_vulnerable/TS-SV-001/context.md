# TS-SV-001: Web IDE Coding Agent — Unsanitised Command Runner

## Scenario

A web-IDE coding agent accepts natural-language prompts from the user, runs
them through an LLM planner that produces a sequence of shell commands (type-
check, test, lint, build), and dispatches each command to a tool runner for
execution. The planner simulates a compromised or prompt-injected model that
includes a malicious `curl` exfiltration payload among otherwise legitimate
developer commands.

## Vulnerability

The `command_runner.ts` tool receives shell command strings directly from the
agent planner and passes them verbatim to `child_process.exec()`. There is no
validation against the `KNOWN_COMMANDS` allowlist defined in
`config/settings.ts`, and `exec()` interprets the string through a shell,
enabling full shell expansion, pipes, and command chaining.

## Why this is vulnerable

- **Source**: LLM planner output (`planner.ts` returns model-controlled shell
  fragments in the `command` field of each `PlanStep`)
- **Carrier**: Agent router (`router.ts`) passes `step.command` directly to
  `runCommand()`
- **Sink**: `child_process.exec(command)` in `command_runner.ts`
- **Missing guard**: No command allowlist enforcement, no use of `execFile()`
  with an explicit argv array

## What a scanner should find

A finding on `command_runner.ts` lines 22-52 indicating that untrusted
(model-controlled) input reaches `child_process.exec()` without command
validation or allowlist enforcement.
