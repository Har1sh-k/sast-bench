# RS-MI-001: Local Ops Assistant — Safe Allowlisted Maintenance vs Unsafe Debug Passthrough

## Scenario

A local ops assistant agent helps system administrators perform routine
maintenance and ad-hoc debugging on servers. An LLM planner generates a
task list based on the requested operation mode. Tasks are dispatched by
a router to one of two tools:

1. **Maintenance tool** — runs system health commands (disk usage, uptime,
   service status) that are checked against a hardcoded allowlist before
   execution.
2. **Debug exec tool** — runs arbitrary diagnostic commands forwarded
   directly from the planner without any validation.

Both tools ultimately call `Command::new("sh").arg("-c").arg(cmd)` to
execute shell commands. The difference is entirely in whether the command
is validated before reaching that sink.

## Safe path (R1 — maintenance tool)

The maintenance tool in `src/tools/maintenance.rs` calls
`command_policy::is_command_allowed(cmd)` before executing anything. The
allowlist in `src/guards/command_policy.rs` contains only specific,
pre-approved commands like `"df -h"`, `"uptime"`, and
`"systemctl status nginx"`. The comparison is exact (byte-for-byte) with
no shell expansion or prefix matching.

Even if the LLM planner produces a malicious command and routes it to the
maintenance tool, the allowlist check will reject it before it reaches
the shell. This makes the maintenance tool safe despite using
`Command::new("sh")`.

## Vulnerable path (R2 — debug exec tool)

The debug exec tool in `src/tools/debug_exec.rs` accepts a command string
from the planner and passes it directly to `sh -c` without any validation,
allowlist check, or sandboxing. If the LLM planner produces a malicious
command — through prompt injection, hallucination, or a confused-deputy
scenario — it will be executed with the full privileges of the host process.

- **Source**: LLM planner output (model-controlled command string)
- **Carrier**: Agent router dispatches `DebugExec` tasks to `debug_exec.rs`
- **Sink**: `Command::new("sh").arg("-c").arg(cmd)` in `debug_exec.rs`
- **Missing guard**: No allowlist check, no sanitization, no sandboxing

## What a scanner should find

A scanner **must** flag `debug_exec.rs` lines 23-46 as a command injection
vulnerability: untrusted input from the LLM planner flows to a shell
execution sink without any guard.

A scanner **must not** flag `maintenance.rs` lines 16-48. Although the
same `Command::new("sh")` pattern is used, the allowlist guard ensures
that only pre-approved commands can reach the shell. Flagging this as
vulnerable would be a false positive.
