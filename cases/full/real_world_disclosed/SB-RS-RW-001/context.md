# SB-RS-RW-001: Codex CLI sandbox bypass via model-controlled cwd

## Advisory
- Repo: `openai/codex`
- GHSA: `GHSA-w5fx-fh39-j5rw`
- CVE: `CVE-2025-59532`
- Vulnerable commit: `62258df92fd1a6165c0497591cc1281f36212939`
- Fix commit: `8595237505a1e0faabc2af3db805b66ce3ae182d`
- Patched in: rust-v0.39.0

## Scenario

Codex CLI is a Rust-based coding agent that executes shell commands
inside a filesystem sandbox (macOS Seatbelt or Linux Landlock). The
sandbox restricts writes to a set of allowed roots derived from the
user's working directory.

## Vulnerability

`process_exec_tool_call` in `exec.rs` receives an `ExecParams` struct
whose `cwd` field comes from the model's tool-call response. This single
`cwd` is used for two purposes:

1. The working directory of the spawned command
2. The input to `SandboxPolicy::get_writable_roots_with_cwd(cwd)`, which
   determines the sandbox's writable filesystem boundary

A model-generated `cwd` pointing to `/etc`, `/home/user/.ssh`, or any
other sensitive path causes the sandbox to whitelist that directory for
writes, effectively escaping the intended workspace boundary.

## Source / Carrier / Sink
- Source: model tool-call output (`cwd` field in `ExecParams`)
- Carrier: `process_exec_tool_call` passes `params.cwd` to sandbox spawners
- Sink: `sandbox_policy.get_writable_roots_with_cwd(cwd)` in seatbelt.rs
  and the equivalent landlock policy in the Linux path
- Missing guard: no validation that `cwd` matches the user's session
  start directory; fix splits into `command_cwd` vs `sandbox_policy_cwd`

## Annotated Region
- File: `codex-rs/core/src/exec.rs`
- Lines: 81-129
- Why this region is the scoring target: it contains
  `process_exec_tool_call` where model-controlled `params.cwd` flows
  into both `spawn_command_under_seatbelt` and
  `spawn_command_under_linux_sandbox` without separating the command
  working directory from the sandbox policy root

## Scanner Expectation
A scanner should flag the flow from the untrusted `cwd` parameter through
to the sandbox policy construction, identifying that a model-controlled
path determines the sandbox writable boundary.
