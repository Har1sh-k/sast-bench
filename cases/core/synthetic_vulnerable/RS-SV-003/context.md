# SB-RS-SV-003: File Sync Agent — TOCTOU Race in Path Validation

## Scenario

A file sync agent backs up files within a workspace boundary. An LLM planner
produces copy tasks with source and destination paths. The agent has a path
guard that canonicalizes each path and verifies it stays within the workspace
root before allowing the operation.

## Why it is vulnerable

The path guard (`guards/path_guard.rs`) validates the path and returns the
canonicalized result. The file sync tool (`tools/file_sync.rs`) then passes
the **original un-canonicalized path** to `fs::copy` in a separate step.

Between validation (step 1) and copy (step 3), an attacker can replace the
source file with a symlink pointing outside the workspace:

1. Guard canonicalizes `data/report.txt` → `/workspace/data/report.txt` ✓
2. Attacker swaps `data/report.txt` → symlink to `/etc/shadow`
3. `fs::copy` follows the current symlink → reads `/etc/shadow`

This is a classic Time-of-Check to Time-of-Use (TOCTOU) race condition.

## What scanners should find

A scanner should flag the gap between path validation and filesystem use in
`tools/file_sync.rs`. The `fs::copy` call at line ~59 uses `abs_source`
(the original path) rather than opening the already-validated file handle,
allowing symlink substitution between check and use.

## Source → Carrier → Sink

- **Source**: LLM planner output (file paths in sync tasks)
- **Carrier**: path guard validates then returns, tool uses path later
- **Sink**: `fs::copy` follows the current filesystem state, not the validated snapshot
- **Missing guard**: re-canonicalization or O_NOFOLLOW immediately before use
