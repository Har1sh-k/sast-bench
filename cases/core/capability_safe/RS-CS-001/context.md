# RS-CS-001: File Organizer Agent — Canonicalized Workspace-Root Guard

## Scenario

A file organizer agent automates tidying up project directories. An LLM
planner analyzes the workspace and suggests tasks such as moving source files
into categorized subdirectories, renaming files to match conventions, or
copying templates into new locations. The agent's file mover tool carries out
these filesystem operations.

## Why this code is SAFE

The `file_mover.rs` tool performs `std::fs::rename`, `std::fs::copy`, and
`std::fs::create_dir_all` operations that may look dangerous to a static
analysis scanner. However, every path is protected by a strict workspace-root
guard implemented in `workspace_guard.rs`:

1. **Canonicalization**: Both source and destination paths are resolved to
   their canonical (absolute, symlink-resolved) form using
   `std::fs::canonicalize()` for existing paths and a manual canonicalization
   for not-yet-existing destination paths (canonicalizing the parent directory
   and appending the file name).

2. **Containment check**: After canonicalization, the guard verifies that the
   resolved path `starts_with()` the canonicalized workspace root. This
   defeats `../` traversal sequences, symlink escapes, and any other
   technique that would resolve outside the workspace.

3. **Fail-closed design**: If canonicalization fails (e.g., the parent
   directory does not exist) or the containment check fails, the operation is
   rejected with a clear error — no filesystem mutation occurs.

4. **Guard is non-bypassable**: The router dispatches every task through the
   file mover tool, and the file mover tool calls the workspace guard before
   every operation. There is no alternative code path that skips the check.

## What a scanner should NOT flag

The filesystem operations in `file_mover.rs` (lines 25-122) are properly
guarded. A scanner that flags this region would be producing a false positive,
penalizing safe, well-structured agent code.
