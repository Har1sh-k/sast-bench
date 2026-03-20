# PY-SV-004: RAG Coding Assistant — Poisoned Knowledge Store Command Injection

## Scenario

A RAG-based coding assistant helps developers run tests for their projects.
The assistant retrieves relevant context snippets from a local JSON knowledge
store (`store/knowledge.json`), then uses the retrieved context to construct
a shell command that runs the appropriate test suite. The knowledge store is
populated over time with project notes, configuration hints, and test
instructions.

## Vulnerability

The `test_runner.py` tool receives retrieved context snippets and
string-interpolates them directly into a shell command template passed to
`subprocess.run` with `shell=True`. An attacker who can write entries to the
knowledge store (e.g., via a shared workspace, a poisoned import, or a
compromised data pipeline) can embed shell metacharacters in a context
snippet. When the assistant later retrieves that snippet and builds its test
command, the injected payload executes.

## Why this is vulnerable

- **Source**: Knowledge store entries (previously written by untrusted parties)
- **Carrier**: Retriever fetches snippets; router passes them to the test runner
- **Sink**: `subprocess.run(cmd, shell=True)` in `test_runner.py`
- **Missing guard**: No sanitisation of retrieved context before shell interpolation

## What a scanner should find

A finding on `test_runner.py` lines 22-64 indicating that untrusted data
from the knowledge store is string-interpolated into a shell command passed
to `subprocess.run` with `shell=True`, enabling command injection.
