# RS-SV-002: Local Build Helper Agent — Command Injection via Task Parameters

## Scenario

A local CI/build helper agent automates common development tasks (building,
testing, linting) for a Rust project. An LLM planner produces a list of build
tasks with parameters such as target names, feature flags, and test filters.
A build runner tool constructs shell commands from these parameters and executes
them via `sh -c`.

## Vulnerability

The `build_runner.rs` tool concatenates task parameters directly into a shell
command string and passes the result to `Command::new("sh").arg("-c").arg(cmd)`.
No allowlist or sanitisation is applied to the parameters before interpolation.
An attacker who controls or influences the planner output can inject arbitrary
shell commands through crafted target names or test filter strings.

## Why this is vulnerable

- **Source**: LLM planner output (model-controlled task parameters)
- **Carrier**: Agent router forwards planner tasks to the build runner tool
- **Sink**: `Command::new("sh").arg("-c").arg(cmd)` in `build_runner.rs`
- **Missing guard**: No allowlist validation on target names, feature flags,
  or test filters before shell interpolation

## What a scanner should find

A finding on `build_runner.rs` lines 23-100 indicating that untrusted input is
interpolated into a shell command string passed to `sh -c`, enabling command
injection.
