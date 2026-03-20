"""SASTbench adapter for securevibes-agent.

Runs securevibes-agent in bootstrap mode on a case directory and normalizes
output to the benchmark's canonical finding format.

securevibes-agent is an LLM-backed security scanner that produces file-level
findings (no line numbers). The adapter maps vulnerability classes to canonical
kinds and uses whole-file line ranges for scoring overlap.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SECUREVIBES_AGENT_DIR = Path(os.environ.get(
    "SECUREVIBES_AGENT_DIR",
    r"D:\GIT\git repos\securevibes-agent",
))

# fnm-managed Node.js isn't always on the Windows system PATH that Python
# inherits.  Resolve a stable node directory once at import time.
_FNM_NODE_DIR = os.environ.get("FNM_NODE_DIR", "")
if not _FNM_NODE_DIR:
    _candidate = Path.home() / "AppData" / "Roaming" / "fnm" / "node-versions"
    if _candidate.exists():
        versions = sorted(_candidate.iterdir(), reverse=True)
        if versions:
            _FNM_NODE_DIR = str(versions[0] / "installation")

# Map securevibes-agent vulnerability classes to canonical kinds.
# Classes that don't map to the V1 taxonomy get "unmapped".
VULN_CLASS_MAP = {
    "commandinjection": "command_injection",
    "codeexec": "command_injection",
    "sandboxescape": "path_traversal",
    # Others don't map cleanly to the 3 V1 canonical kinds
    "xss": "unmapped",
    "authbypass": "unmapped",
    "brokenauthz": "unmapped",
    "abuse": "unmapped",
    "inputvalidation": "unmapped",
    "secretdisclosure": "unmapped",
    "newattacksurface": "unmapped",
}

# Pattern-based fallback for vulnerability classes or titles
VULN_PATTERN_MAP = {
    "command": "command_injection",
    "exec": "command_injection",
    "injection": "command_injection",
    "shell": "command_injection",
    "subprocess": "command_injection",
    "sandbox": "path_traversal",
    "path": "path_traversal",
    "traversal": "path_traversal",
    "directory": "path_traversal",
    "workspace": "path_traversal",
    "ssrf": "ssrf",
    "request-forgery": "ssrf",
    "url": "ssrf",
    "fetch": "ssrf",
}


def get_version() -> str:
    """Get the securevibes-agent version string."""
    pkg_json = SECUREVIBES_AGENT_DIR / "package.json"
    try:
        with open(pkg_json) as f:
            pkg = json.load(f)
        return pkg.get("version", "unknown")
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def map_vuln_class(vuln_class: str, title: str = "") -> str:
    """Map a securevibes-agent vulnerability class to a canonical kind."""
    normalized = vuln_class.lower().strip()
    if normalized in VULN_CLASS_MAP:
        kind = VULN_CLASS_MAP[normalized]
        if kind != "unmapped":
            return kind

    # Try pattern matching on the class + title
    combined = f"{normalized} {title.lower()}"
    for pattern, kind in VULN_PATTERN_MAP.items():
        if pattern in combined:
            return kind

    return "unmapped"


def severity_map(sv_severity: str) -> str:
    """Map securevibes-agent severity to benchmark severity."""
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get(sv_severity.lower(), "medium")


def _count_lines(file_path: Path) -> int:
    """Count lines in a file for whole-file region."""
    try:
        return len(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 1


def _extract_json(text: str) -> dict | None:
    """Extract JSON object from potentially mixed output."""
    # Try parsing the whole thing first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try each line (the --json flag prints one JSON object)
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def _build_env() -> dict[str, str]:
    """Build a subprocess environment with Node.js on PATH."""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if _FNM_NODE_DIR:
        sep = ";" if sys.platform == "win32" else ":"
        env["PATH"] = _FNM_NODE_DIR + sep + env.get("PATH", "")
    return env


def _read_finding_files(findings_dir: Path) -> list[dict]:
    """Read finding records from .securevibes/findings/ markdown files.

    This gives richer data than the JSON summary because the knowledge
    base files always have the latest file_path and vulnerability_class.
    """
    records = []
    if not findings_dir.exists():
        return records
    for md in sorted(findings_dir.glob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        # Parse YAML-ish frontmatter between --- fences
        if not text.startswith("---"):
            continue
        end = text.index("---", 3)
        fm_text = text[3:end]
        record: dict = {}
        for line in fm_text.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            val = val.strip().strip('"').strip("'")
            record[key.strip()] = val
        if record.get("id"):
            records.append(record)
    return records


def scan(scan_root: Path, language: str) -> list[dict]:
    """Run securevibes-agent on the scan root and return normalized findings."""
    scan_root = scan_root.resolve()

    # Remove any stale .securevibes state so findings are fresh.
    sv_dir = scan_root / ".securevibes"
    if sv_dir.exists():
        shutil.rmtree(sv_dir, ignore_errors=True)

    llm_model = os.environ.get("SECUREVIBES_LLM_MODEL", "anthropic/claude-sonnet-4-5")
    env = _build_env()

    # On Windows subprocess needs the .cmd extension for npm/npx shims.
    npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"

    print("\n", flush=True)
    try:
        # Let stdout and stderr stream to the terminal so the user sees
        # progress in real-time.  We read findings from the .securevibes/
        # knowledge-base files afterward instead of parsing JSON stdout.
        subprocess.run(
            [
                npx_cmd, "tsx",
                str(SECUREVIBES_AGENT_DIR / "src" / "runtime" / "cli.ts"),
                "bootstrap",
                "--repo", str(scan_root),
                "--analysis-mode", "llm",
                "--llm-model", llm_model,
            ],
            cwd=str(SECUREVIBES_AGENT_DIR),
            env=env,
        )
    except FileNotFoundError:
        print("    npx/tsx not found — install Node.js and tsx")
        return []

    # Read findings from the knowledge-base files written by the scan.
    kb_records = _read_finding_files(sv_dir / "findings") if sv_dir.exists() else []

    # Clean up .securevibes after reading
    if sv_dir.exists():
        shutil.rmtree(sv_dir, ignore_errors=True)

    # --- Normalize to SASTbench format ---
    findings = []
    scan_root_str = str(scan_root).replace("\\", "/")

    for record in kb_records:
        file_path = record.get("file_path", "")
        if not file_path:
            continue

        # Normalize path relative to scan_root
        rel_path = file_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")
        rel_path = rel_path.lstrip("./")

        vuln_class = record.get("vulnerability_class", "")
        title = record.get("title", "")
        mapped_kind = map_vuln_class(vuln_class, title)

        # securevibes-agent provides file-level findings without line numbers.
        # Use whole-file range so scoring can match by path overlap.
        abs_file = scan_root / rel_path
        end_line = _count_lines(abs_file) if abs_file.exists() else 9999

        findings.append({
            "ruleId": f"sv-agent:{vuln_class}:{record.get('id', 'unknown')}",
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": 1,
            "endLine": end_line,
            "severity": severity_map(record.get("severity", "medium")),
            "message": title,
        })

    return findings
