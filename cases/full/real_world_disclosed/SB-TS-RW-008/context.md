# SB-TS-RW-008: Workspace path guard bypass on non-existent out-of-root symlink leaf

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-mgrq-9f93-wpp5`
- Vulnerable commit: `ecb2053fdd3fb5c06a0133e844b75c8580fcccd3`
- Fix commit: `46eba86b45e9db05b7b792e914c4fe0de1b40a23`

## Scenario

OpenClaw enforces workspace path boundaries to prevent agents from reading or writing files outside the configured workspace root. The `assertNoPathAliasEscape` function in `path-alias-guards.ts` is the core guard: it walks each segment of a target path, resolves symlinks along the way, and verifies that each resolved symlink target remains within the workspace root. This function is used by sandbox path assertions, workspace file resolution, and boundary file reads throughout the codebase.

## Vulnerability

The `assertNoPathAliasEscape` function (lines 23-68) iterates over path segments and calls `lstat` on each component. When a symlink is found, it resolves the target via `tryRealpath` and checks that the resolved path is inside the root boundary. However, when `lstat` throws an `ENOENT` error (the segment does not exist), the function immediately breaks out of the loop at line 61 without performing any further checks. This creates a bypass: an attacker can create a symlink inside the workspace that points to a directory outside the root (e.g., `/tmp/outside`), then request a path like `workspace/escape-link/new-file.txt`. The function walks to `escape-link`, finds it is a symlink, and resolves it. But if `new-file.txt` does not yet exist under the resolved symlink target, `lstat` on the full path throws ENOENT and the loop breaks -- critically, the function has already updated `current` to the symlink's resolved target but the ENOENT occurs on the *next* segment, and the `break` exits before the escape is caught. This enables first-write sandbox escapes where a file is created at an out-of-root location via a symlink alias.

## Source / Carrier / Sink
- Source: attacker-controlled file path containing a symlink component pointing outside the workspace root
- Carrier: the `catch` block at line 60 catches `ENOENT` from `lstat` on a non-existent leaf and breaks the loop, skipping further symlink resolution
- Sink: the function returns without throwing, allowing the caller to proceed with a write operation at the out-of-root symlink target path
- Missing guard: the fix replaces the per-segment walk with a `resolveBoundaryPath` helper that resolves the path via existing ancestors (walking up to find the nearest existing parent, resolving its realpath, then appending the remaining segments) to ensure symlink resolution is performed even when the leaf does not exist

## Scanner Expectation
A scanner should flag the ENOENT handling in the path segment walk (lines 60-62) for breaking out of the symlink validation loop prematurely. The vulnerability is a path traversal / sandbox escape where non-existent leaf segments cause the symlink containment check to be skipped, allowing writes through out-of-root symlink aliases.
