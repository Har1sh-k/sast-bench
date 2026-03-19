# PY-SV-002: Document Export Assistant — Unvalidated Output Path

## Scenario

A document export assistant generates reports (PDF summaries, CSV extracts)
and writes them to an output path chosen by the user.

## Vulnerability

The `file_writer.py` tool joins a user-provided filename with a base output
directory using `os.path.join`, but never resolves or validates that the
resulting path stays within the workspace root. A path like
`../../../etc/cron.d/backdoor` escapes the intended directory.

## Why this is vulnerable

- **Source**: User-provided output filename
- **Carrier**: Agent planner passes the filename to the file writer tool
- **Sink**: `open(full_path, "w")` in `file_writer.py`
- **Missing guard**: No `os.path.realpath` + prefix check against workspace root

## What a scanner should find

A finding on `file_writer.py` lines 12-35 indicating that a user-controlled
path reaches a file-write operation without workspace-root enforcement.
