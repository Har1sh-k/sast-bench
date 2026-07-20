"""SASTbench adapter for JFrog USAF (usaf_cli).

Invokes ``usaf analyze`` (or a configured CLI) with a rules JSON and
normalizes SARIF results into SASTbench findings.

Environment variables
---------------------
USAF_CLI
    Path to the ``usaf`` / ``usaf_cli`` executable. Required for scans.
USAF_RULES_JSON
    Absolute path to ``dist/rules.json``. Required for scans.
USAF_TIMEOUT
    Per-case scan timeout in seconds (default: 300).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse

ADAPTER_VERSION = "1.0.0"

SUPPORTED_LANGUAGES = {
    "python": "python",
    "typescript": "javascript",
    "javascript": "javascript",
    "rust": "rust",
    "go": "go",
    "java": "java",
}

# Direct rule-id → kind (USAF rule ids are kebab-case, often language-prefixed).
RULE_KIND_MAP: dict[str, str] = {
    # Command / RCE
    "python-command-injection": "command_injection",
    "python-stored-command-injection": "command_injection",
    "python-tainted-os-command": "command_injection",
    "python-stored-tainted-os-command": "command_injection",
    "python-code-injection": "command_injection",
    "javascript-command-injection": "command_injection",
    "js-command-injection": "command_injection",
    "rust-command-injection": "command_injection",
    "go-command-injection": "command_injection",
    "java-command-injection": "command_injection",
    # Path
    "python-path-traversal": "path_traversal",
    "python-stored-path-traversal": "path_traversal",
    "javascript-path-traversal": "path_traversal",
    "js-path-traversal": "path_traversal",
    "rust-path-traversal": "path_traversal",
    "go-path-traversal": "path_traversal",
    "java-path-traversal": "path_traversal",
    # SSRF
    "python-ssrf": "ssrf",
    "python-partial-ssrf": "ssrf",
    "javascript-ssrf": "ssrf",
    "js-ssrf": "ssrf",
    "js-partial-ssrf": "ssrf",
    "rust-ssrf": "ssrf",
    "go-ssrf": "ssrf",
    "java-ssrf": "ssrf",
    "java-partial-ssrf": "ssrf",
    # SQL
    "python-sql-injection": "sql_injection",
    "python-2nd-order-sql-injection": "sql_injection",
    "javascript-sql-injection": "sql_injection",
    "js-sql-injection": "sql_injection",
    "rust-sql-injection": "sql_injection",
    "go-sql-injection": "sql_injection",
    "java-sql-injection": "sql_injection",
    "java-2nd-order-sql-injection": "sql_injection",
}

# Conservative substring fallbacks (checked after exact map).
RULE_PATTERN_MAP: dict[str, str] = {
    "command-injection": "command_injection",
    "tainted-os-command": "command_injection",
    "code-injection": "command_injection",
    "path-traversal": "path_traversal",
    "partial-ssrf": "ssrf",
    "ssrf": "ssrf",
    "2nd-order-sql": "sql_injection",
    "sql-injection": "sql_injection",
    "authz": "authz_bypass",
    "authorization": "authz_bypass",
    "auth-bypass": "auth_bypass",
    "authentication": "auth_bypass",
}

# CWE → kind when rule id does not map (from SARIF properties or rules.json).
CWE_KIND_MAP: dict[str, str] = {
    "78": "command_injection",
    "77": "command_injection",
    "88": "command_injection",
    "94": "command_injection",
    "22": "path_traversal",
    "23": "path_traversal",
    "36": "path_traversal",
    "918": "ssrf",
    "89": "sql_injection",
    "564": "sql_injection",
    "287": "auth_bypass",
    "306": "auth_bypass",
    "862": "authz_bypass",
    "863": "authz_bypass",
    "285": "authz_bypass",
}

_RULES_CWE_CACHE: dict[str, str] | None = None


def get_version() -> str:
    """Return USAF CLI version string."""
    cli = os.environ.get("USAF_CLI", "").strip()
    if not cli:
        return "unknown"
    try:
        result = subprocess.run(
            [cli, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        text = (result.stdout or result.stderr or "").strip()
        return text.split("\n")[0] if text else "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "unknown"


def map_rule_to_kind(rule_id: str, cwe: str | None = None) -> str:
    """Map a USAF rule id (and optional CWE) to a canonical kind."""
    if rule_id in RULE_KIND_MAP:
        return RULE_KIND_MAP[rule_id]

    rule_lower = rule_id.lower()
    for pattern, kind in RULE_PATTERN_MAP.items():
        if pattern in rule_lower:
            return kind

    if cwe:
        cwe_num = str(cwe).lstrip("CWE-cwe").split(",")[0].strip()
        if cwe_num in CWE_KIND_MAP:
            return CWE_KIND_MAP[cwe_num]

    cached = _cwe_from_rules_json(rule_id)
    if cached and cached in CWE_KIND_MAP:
        return CWE_KIND_MAP[cached]

    return "unmapped"


def _cwe_from_rules_json(rule_id: str) -> str | None:
    """Look up CWE for rule_id from USAF_RULES_JSON (cached)."""
    global _RULES_CWE_CACHE
    if _RULES_CWE_CACHE is None:
        _RULES_CWE_CACHE = {}
        path = os.environ.get("USAF_RULES_JSON", "").strip()
        if path and Path(path).is_file():
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if isinstance(data, dict):
                for lang_rules in data.values():
                    if not isinstance(lang_rules, dict):
                        continue
                    for rid, meta in lang_rules.items():
                        if (
                            isinstance(meta, dict)
                            and meta.get("cwe") is not None
                        ):
                            _RULES_CWE_CACHE[rid] = str(meta["cwe"])
    return _RULES_CWE_CACHE.get(rule_id)


def severity_map(level: str) -> str:
    """Map SARIF level to benchmark severity."""
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "low",
    }.get((level or "").lower(), "medium")


def _uri_to_relpath(uri: str, scan_root: Path) -> str:
    """Convert a SARIF artifact URI into a path relative to scan_root."""
    raw = uri or ""
    if raw.startswith("file:"):
        parsed = urlparse(raw)
        raw = unquote(parsed.path)
        # Windows file:///C:/... → path starts with /C:/
        if len(raw) >= 3 and raw[0] == "/" and raw[2] == ":":
            raw = raw[1:]
    path = Path(raw)
    root = scan_root.resolve()
    try:
        if path.is_absolute():
            return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        pass
    # Already relative, or outside root — normalize slashes only.
    return raw.replace("\\", "/").lstrip("./")


def _extract_cwe(result: dict) -> str | None:
    """Best-effort CWE from SARIF result properties / taxa."""
    props = result.get("properties") or {}
    for key in ("cwe", "CWE", "cwe_id"):
        if props.get(key) is not None:
            return str(props[key])
    tags = props.get("tags") or props.get("rule_tags") or []
    if isinstance(tags, list):
        for tag in tags:
            s = str(tag).lower()
            if s.startswith("cwe-") or s.startswith("cwe="):
                return s.split("-", 1)[-1].split("=", 1)[-1]
    return None


def _parse_sarif(sarif: dict, scan_root: Path) -> list[dict]:
    """Normalize SARIF runs into SASTbench findings."""
    findings: list[dict] = []
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "unknown"
            cwe = _extract_cwe(result)
            mapped = map_rule_to_kind(rule_id, cwe)
            locations = result.get("locations") or []
            if not locations:
                continue
            phys = locations[0].get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri") or ""
            region = phys.get("region") or {}
            start = int(region.get("startLine") or 1)
            end = int(region.get("endLine") or start)
            message = ""
            msg = result.get("message")
            if isinstance(msg, dict):
                message = msg.get("text") or ""
            elif isinstance(msg, str):
                message = msg
            findings.append(
                {
                    "ruleId": rule_id,
                    "mappedKind": mapped,
                    "path": _uri_to_relpath(uri, scan_root),
                    "startLine": start,
                    "endLine": end,
                    "severity": severity_map(result.get("level") or ""),
                    "message": message,
                }
            )
    return findings


def _missing_env_result(
    command: list[str] | None, reason: str, detail: str
) -> dict:
    return {
        "findings": [],
        "commandInvocation": command,
        "exitCode": None,
        "rawStdout": "",
        "rawStderr": detail,
        "skipReason": reason,
    }


def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Run USAF and return findings plus raw scanner metadata."""
    lang = SUPPORTED_LANGUAGES.get(language)
    if lang is None:
        return _missing_env_result(
            None,
            "language_not_supported",
            f"USAF adapter does not support language={language!r}",
        )

    cli = os.environ.get("USAF_CLI", "").strip()
    rules = os.environ.get("USAF_RULES_JSON", "").strip()
    if not cli:
        return _missing_env_result(
            None,
            "scanner_not_installed",
            "USAF_CLI is not set — point it at usaf_cli / usaf analyze binary",
        )
    if not rules or not Path(rules).is_file():
        return _missing_env_result(
            None,
            "scanner_not_installed",
            "USAF_RULES_JSON must point to an existing dist/rules.json",
        )

    timeout = int(os.environ.get("USAF_TIMEOUT", "300"))
    scan_root = Path(scan_root)

    with tempfile.TemporaryDirectory(prefix="sastbench-usaf-") as tmp:
        sarif_path = Path(tmp) / "out.sarif"
        command = [
            cli,
            "analyze",
            str(sarif_path),
            str(scan_root),
            "--language",
            lang,
            "--rules",
            rules,
        ]
        # Optional. Unset → USAF default excludes (skips node_modules etc.).
        # Set to empty string to disable excludes (useful for tiny Core cases).
        if "USAF_EXCLUDE_PATTERNS" in os.environ:
            command.extend(
                ["--exclude-patterns", os.environ["USAF_EXCLUDE_PATTERNS"]]
            )
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return _missing_env_result(
                command,
                "scanner_not_installed",
                f"USAF CLI not found at {cli}",
            )
        except subprocess.TimeoutExpired:
            return {
                "findings": [],
                "commandInvocation": command,
                "exitCode": None,
                "rawStdout": "",
                "rawStderr": f"usaf timed out after {timeout}s",
                "skipReason": "timeout",
            }

        raw_stdout = result.stdout or ""
        raw_stderr = result.stderr or ""
        findings: list[dict] = []
        if sarif_path.is_file():
            try:
                sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
                findings = _parse_sarif(sarif, scan_root)
            except (OSError, json.JSONDecodeError) as exc:
                raw_stderr = f"{raw_stderr}\nSARIF parse error: {exc}".strip()

        return {
            "findings": findings,
            "commandInvocation": command,
            "exitCode": result.returncode,
            "rawStdout": raw_stdout,
            "rawStderr": raw_stderr,
            "skipReason": None,
        }


def scan(scan_root: Path, language: str) -> list[dict]:
    """Backward-compatible findings-only wrapper."""
    return scan_with_metadata(scan_root, language)["findings"]
