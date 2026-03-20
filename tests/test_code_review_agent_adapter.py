"""Tests for the code-review-agent adapter."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parent.parent


def load_adapter():
    path = REPO_ROOT / "adapters" / "code-review-agent" / "adapter.py"
    spec = importlib.util.spec_from_file_location("test_code_review_agent_adapter", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_map_finding_ignores_reasoning_for_unknown_cwe():
    adapter = load_adapter()

    finding = {
        "title": "Content-Length Header Integer Injection / Bypass",
        "reasoning": "This might eventually reach command execution in some scenarios.",
        "cwe": "CWE-400",
    }

    assert adapter._map_finding(finding) == "unmapped"


def test_scan_filters_review_noise_and_prefers_sink_localization(monkeypatch, tmp_path):
    adapter = load_adapter()
    scan_root = tmp_path
    (scan_root / "tools").mkdir()
    (scan_root / "agent").mkdir()
    (scan_root / "app").mkdir()

    sink_path = scan_root / "tools" / "reference_fetcher.py"
    sink_path.write_text("import requests\n", encoding="utf-8")
    router_path = scan_root / "agent" / "router.py"
    router_path.write_text("from tools.reference_fetcher import fetch_reference\n", encoding="utf-8")
    main_path = scan_root / "app" / "main.py"
    main_path.write_text("print('hello')\n", encoding="utf-8")

    payload = {
        "findings": [
            {
                "category": "security",
                "cwe": "CWE-918",
                "title": "SSRF via Unrestricted URL Fetching",
                "severity": "critical",
                "location": {
                    "file": str(sink_path),
                    "startLine": 21,
                    "endLine": 61,
                },
            },
            {
                "category": "security",
                "cwe": "CWE-918",
                "title": "Unvalidated URL passed to fetch_reference - SSRF risk",
                "severity": "high",
                "location": {
                    "file": str(router_path),
                    "startLine": 32,
                    "endLine": 50,
                },
            },
            {
                "category": "unhandled-exception",
                "cwe": "CWE-754",
                "title": "Unhandled exception if execute_plan returns non-iterable",
                "severity": "medium",
                "location": {
                    "file": str(main_path),
                    "startLine": 27,
                    "endLine": 31,
                },
            },
            {
                "category": "logic-bug",
                "cwe": "CWE-400",
                "title": "Content-Length Header Integer Injection / Bypass",
                "reasoning": "This might eventually reach command execution in some scenarios.",
                "severity": "medium",
                "location": {
                    "file": str(sink_path),
                    "startLine": 36,
                    "endLine": 42,
                },
            },
            {
                "category": "security",
                "title": "Unvalidated command-line input passed directly to agent pipeline at system boundary",
                "reasoning": "The input might later reach a shell.",
                "severity": "low",
                "location": {
                    "file": str(main_path),
                    "startLine": 38,
                    "endLine": 38,
                },
            },
        ]
    }

    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps(payload))

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    findings = adapter.scan(scan_root, "python")

    assert findings == [
        {
            "ruleId": "cr-agent:security:CWE-918",
            "mappedKind": "ssrf",
            "path": "tools/reference_fetcher.py",
            "startLine": 21,
            "endLine": 61,
            "severity": "critical",
            "message": "SSRF via Unrestricted URL Fetching",
        }
    ]


def test_scan_keeps_title_matched_non_cwe_security_finding(monkeypatch, tmp_path):
    adapter = load_adapter()
    scan_root = tmp_path
    (scan_root / "src").mkdir()
    target = scan_root / "src" / "handler.ts"
    target.write_text("export {};\n", encoding="utf-8")

    payload = {
        "findings": [
            {
                "category": "security",
                "title": "Authentication bypass via missing token validation",
                "severity": "high",
                "location": {
                    "file": str(target),
                    "startLine": 10,
                    "endLine": 20,
                },
            }
        ]
    }

    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps(payload))

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    findings = adapter.scan(scan_root, "typescript")

    assert findings == [
        {
            "ruleId": "cr-agent:security",
            "mappedKind": "auth_bypass",
            "path": "src/handler.ts",
            "startLine": 10,
            "endLine": 20,
            "severity": "high",
            "message": "Authentication bypass via missing token validation",
        }
    ]
