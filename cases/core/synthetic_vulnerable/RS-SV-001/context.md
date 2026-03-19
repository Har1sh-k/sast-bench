# RS-SV-001: Workspace Refactor Agent — Unvalidated Plan-Step File Paths

## Scenario

A workspace refactor agent automates large-scale code transformations across a
Rust project. An LLM planner produces a sequence of refactoring steps — rename
a symbol, move a function between modules, update import paths — and each step
includes the relative file path within the workspace that should be rewritten.
The agent's file writer tool applies the rewritten content to disk.

## Vulnerability

The `file_writer.rs` tool receives a relative path from each plan step and
joins it with the workspace root using `Path::join`. However, it never
canonicalizes the resulting path or checks that it remains under the workspace
root. A plan step containing `../` segments (e.g.,
`../../../etc/cron.d/backdoor`) can escape the workspace and overwrite
arbitrary files on the filesystem.

## Why this is vulnerable

- **Source**: LLM planner output (model-controlled relative file path)
- **Carrier**: Agent router passes the plan-step path to the file writer tool
- **Sink**: `std::fs::write(full_path, &content)` in `file_writer.rs`
- **Missing guard**: No `std::fs::canonicalize()` + `starts_with()` check
  against the workspace root

## What a scanner should find

A finding on `file_writer.rs` lines 29-63 indicating that an untrusted
path reaches a file-write operation without workspace-root enforcement via
canonicalization.
