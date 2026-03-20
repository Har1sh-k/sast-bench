# PY-SV-003: Task Assistant Agent — Unsanitised Command Construction

## Scenario

A task assistant agent accepts natural-language messages from users describing
tasks to execute. The agent's planner parses the message into structured task
objects (with a name and description), and the router dispatches each task to
the appropriate tool. The task executor tool constructs a shell command by
string-formatting the user-supplied task description directly into a command
template and passes it to `subprocess.run` with `shell=True`.

## Vulnerability

The `task_executor.py` tool receives task descriptions that originate from
user input and interpolates them directly into a shell command string. There
is no sanitisation or escaping of shell metacharacters, allowing an attacker
to inject arbitrary commands via the task description field.

## Why this is vulnerable

- **Source**: User-supplied task description (via the planner)
- **Carrier**: Agent router passes structured task objects to the executor tool
- **Sink**: `subprocess.run(cmd, shell=True)` in `task_executor.py`
- **Missing guard**: No shell escaping, no input sanitisation, no command allowlist

## What a scanner should find

A finding on `task_executor.py` lines 20-52 indicating that untrusted input
is string-interpolated into a shell command passed to `subprocess.run` with
`shell=True`, enabling command injection.
