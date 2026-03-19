"""SASTbench adapter for Bandit.

Runs Bandit on a case directory and normalizes output to the
benchmark's canonical finding format. Bandit only supports Python.
"""

import json
import subprocess
from pathlib import Path

# Bandit test ID to canonical kind mapping
TEST_KIND_MAP = {
    # Subprocess / command injection
    "B602": "command_injection",  # subprocess_popen_with_shell_equals_true
    "B603": "command_injection",  # subprocess_without_shell_equals_true
    "B604": "command_injection",  # any_other_function_with_shell_equals_true
    "B605": "command_injection",  # start_process_with_a_shell
    "B606": "command_injection",  # start_process_with_no_shell
    "B607": "command_injection",  # start_process_with_partial_path
    # os.system / exec
    "B102": "command_injection",  # exec_used
    # Network / SSRF
    "B310": "ssrf",  # urllib_urlopen
    "B309": "ssrf",  # httpsconnection
    # File / path
    "B108": "path_traversal",  # hardcoded_tmp_directory
}

# Broader pattern matching
TEST_NAME_MAP = {
    "subprocess": "command_injection",
    "exec": "command_injection",
    "system": "command_injection",
    "popen": "command_injection",
    "urlopen": "ssrf",
    "request": "ssrf",
}


def get_version() -> str:
    """Get the Bandit version string."""
    try:
        result = subprocess.run(
            ["bandit", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        first_line = result.stdout.strip().split("\n")[0]
        return first_line.replace("bandit ", "").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def map_test_to_kind(test_id: str, test_name: str) -> str:
    """Map a Bandit test to a canonical benchmark kind."""
    if test_id in TEST_KIND_MAP:
        return TEST_KIND_MAP[test_id]

    name_lower = test_name.lower()
    for pattern, kind in TEST_NAME_MAP.items():
        if pattern in name_lower:
            return kind

    return "unmapped"


def severity_map(bandit_severity: str) -> str:
    """Map Bandit severity to benchmark severity."""
    return {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(bandit_severity, "medium")


def scan(scan_root: Path, language: str) -> list[dict]:
    """Run Bandit on the scan root and return normalized findings."""
    if language != "python":
        return []

    try:
        result = subprocess.run(
            [
                "bandit",
                "-r",
                "-f", "json",
                str(scan_root),
            ],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        print("    bandit not found — install with: pip install bandit")
        return []
    except subprocess.TimeoutExpired:
        print("    bandit timed out")
        return []

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    scan_root_str = str(scan_root.resolve()).replace("\\", "/")

    for issue in output.get("results", []):
        abs_path = issue.get("filename", "")
        rel_path = abs_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")

        test_id = issue.get("test_id", "")
        test_name = issue.get("test_name", "")
        mapped_kind = map_test_to_kind(test_id, test_name)

        findings.append({
            "ruleId": f"{test_id}:{test_name}",
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": issue.get("line_number", 1),
            "endLine": issue.get("line_range", [issue.get("line_number", 1)])[-1],
            "severity": severity_map(issue.get("issue_severity", "")),
            "message": issue.get("issue_text", ""),
        })

    return findings
