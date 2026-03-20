# SB-PY-RW-006: Semantic Kernel SessionsPythonPlugin arbitrary file read/write via path traversal

## Advisory
- Repo: `microsoft/semantic-kernel`
- GHSA: `GHSA-2ww3-72rp-wpp4`
- CVE: `CVE-2026-25592`
- Vulnerable commit: `2a47ba9b7da63bb7df219f7a4480ca8c4cf95ed4`
- Fix commit: `5b27a727a2190d8c251f17e0a0fbb78a3c59d96f` (merge of PR #13478)
- Fix implementation commit: `e696dc7d525b5d7dc664318bbdee6d3e008a3db5`

## Scenario

Microsoft Semantic Kernel is an SDK for building AI agents that can call
"kernel functions" (tool plugins). The `SessionsPythonTool` plugin lets
an agent execute Python code in Azure Container Apps dynamic sessions,
and includes `upload_file` and `download_file` functions to move files
between the local filesystem and the remote session.

## Vulnerability

Both `upload_file` (line 258) and `download_file` (line 338) accept a
`local_file_path` parameter from the AI agent and pass it directly to
`open()` without any path validation, canonicalization, or directory
restriction:

- `upload_file`: `open(local_file_path, "rb")` reads an arbitrary local
  file and uploads its contents to the remote session.
- `download_file`: `open(local_file_path, "wb")` writes remote session
  content to an arbitrary local path.

An attacker who can influence the agent's tool-call arguments (e.g.,
through prompt injection) can use path traversal sequences like
`../../etc/passwd` or absolute paths like `/etc/shadow` to read or
overwrite any file accessible to the process.

## Source / Carrier / Sink
- Source: `local_file_path` parameter supplied by the AI agent's
  tool-call arguments
- Carrier: `upload_file()` and `download_file()` methods in
  `sessions_python_plugin.py`
- Sink: `open(local_file_path, "rb")` at line 258 (arbitrary read),
  `open(local_file_path, "wb")` at line 338 (arbitrary write)
- Missing guard: no path canonicalization, no directory allowlist check,
  no traversal sequence rejection

## Annotated Regions
- File: `python/semantic_kernel/core_plugins/sessions_python_tool/sessions_python_plugin.py`
- R1 (lines 219-270): The `upload_file` method including the unguarded
  `open(local_file_path, "rb")` at line 258 that reads arbitrary files
- R2 (lines 304-347): The `download_file` method including the unguarded
  `open(local_file_path, "wb")` at line 338 that writes arbitrary files

## Scanner Expectation
A scanner should flag at minimum the `upload_file` method (R1) for
passing user-controlled `local_file_path` to `open()` without path
validation, enabling arbitrary file read via path traversal. Detection
of the `download_file` method (R2) is desirable but not required for
passing.
