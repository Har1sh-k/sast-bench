"""SASTbench adapter for code-review-agent.

Runs the LLM-powered code review agent on a case directory and normalizes
findings to the benchmark's canonical format. The agent outputs structured
JSON with file paths, line ranges, severity, CWE, and confidence scores.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

CODE_REVIEW_AGENT_DIR = Path(os.environ.get(
    "CODE_REVIEW_AGENT_DIR",
    r"D:\GIT\git repos\agent-security-scanner-mcp\code-review-agent",
))

# fnm-managed Node.js PATH setup for Windows.
_FNM_NODE_DIR = os.environ.get("FNM_NODE_DIR", "")
if not _FNM_NODE_DIR:
    _candidate = Path.home() / "AppData" / "Roaming" / "fnm" / "node-versions"
    if _candidate.exists():
        versions = sorted(_candidate.iterdir(), reverse=True)
        if versions:
            _FNM_NODE_DIR = str(versions[0] / "installation")

# Map finding categories and CWE IDs to canonical kinds.
CWE_KIND_MAP = {
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-94": "command_injection",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-918": "ssrf",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-862": "authz_bypass",
    "CWE-863": "authz_bypass",
}

# Pattern-based fallback on finding title
TITLE_PATTERN_MAP = {
    "command injection": "command_injection",
    "shell injection": "command_injection",
    "code injection": "command_injection",
    "arbitrary command": "command_injection",
    "code execution": "command_injection",
    "rce": "command_injection",
    "remote code": "command_injection",
    "eval(": "command_injection",
    "subprocess": "command_injection",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "sandbox escape": "path_traversal",
    "sandbox bypass": "path_traversal",
    "workspace escape": "path_traversal",
    "symlink": "path_traversal",
    "ssrf": "ssrf",
    "request forgery": "ssrf",
    "url validation": "ssrf",
    "fetch": "ssrf",
    "auth bypass": "auth_bypass",
    "authentication bypass": "auth_bypass",
    "unauthenticated": "auth_bypass",
    "missing authentication": "auth_bypass",
    "authorization bypass": "authz_bypass",
    "privilege escalation": "authz_bypass",
    "broken authorization": "authz_bypass",
    "scope escalation": "authz_bypass",
    "missing authorization": "authz_bypass",
}


def get_version() -> str:
    """Get the code-review-agent version string."""
    pkg_json = CODE_REVIEW_AGENT_DIR / "package.json"
    try:
        with open(pkg_json) as f:
            pkg = json.load(f)
        return pkg.get("version", "unknown")
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def _map_finding(finding: dict) -> str:
    """Map a finding to a canonical kind using CWE and title patterns."""
    # Try CWE first
    cwe = finding.get("cwe", "")
    if cwe and cwe in CWE_KIND_MAP:
        return CWE_KIND_MAP[cwe]

    # Pattern match on title + reasoning
    text = f"{finding.get('title', '')} {finding.get('reasoning', '')}".lower()
    for pattern, kind in TITLE_PATTERN_MAP.items():
        if pattern in text:
            return kind

    return "unmapped"


def _build_env() -> dict[str, str]:
    """Build a subprocess environment with Node.js on PATH."""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if _FNM_NODE_DIR:
        sep = ";" if sys.platform == "win32" else ":"
        env["PATH"] = _FNM_NODE_DIR + sep + env.get("PATH", "")
    return env


def scan(scan_root: Path, language: str) -> list[dict]:
    """Run code-review-agent on the scan root and return normalized findings."""
    scan_root = scan_root.resolve()
    env = _build_env()
    npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"

    print("\n", flush=True)
    try:
        result = subprocess.run(
            [
                npx_cmd, "tsx",
                str(CODE_REVIEW_AGENT_DIR / "bin" / "cr-agent.ts"),
                "analyze",
                str(scan_root),
                "--format", "json",
                "--confidence", "0.5",
                "--provider", "claude-cli",
            ],
            stdout=subprocess.PIPE,
            stderr=None,  # stream stderr to terminal
            text=True,
            cwd=str(CODE_REVIEW_AGENT_DIR),
            env=env,
        )
    except FileNotFoundError:
        print("    npx/tsx not found — install Node.js and tsx")
        return []

    # Parse JSON output
    output = None
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Try finding JSON in mixed output
        for line in reversed(result.stdout.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    output = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

    if output is None:
        return []

    raw_findings = output.get("findings", [])
    scan_root_str = str(scan_root).replace("\\", "/")

    findings = []
    for f in raw_findings:
        location = f.get("location", {})
        file_path = location.get("file", "")
        if not file_path:
            continue

        # Normalize path relative to scan_root
        rel_path = file_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")
        rel_path = rel_path.lstrip("./")

        mapped_kind = _map_finding(f)
        cwe = f.get("cwe", "")
        category = f.get("category", "")

        findings.append({
            "ruleId": f"cr-agent:{category}:{cwe}" if cwe else f"cr-agent:{category}",
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": location.get("startLine", 1),
            "endLine": location.get("endLine", location.get("startLine", 1)),
            "severity": f.get("severity", "medium"),
            "message": f.get("title", ""),
        })

    return findings
