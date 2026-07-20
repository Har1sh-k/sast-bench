"""Tests for the USAF SASTbench adapter (no live scanner required)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_adapter():
    path = REPO_ROOT / "adapters" / "usaf" / "adapter.py"
    spec = importlib.util.spec_from_file_location("test_usaf_adapter", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_map_rule_to_kind_exact_and_pattern():
    usaf = load_adapter()
    assert usaf.map_rule_to_kind("python-ssrf") == "ssrf"
    assert (
        usaf.map_rule_to_kind("python-command-injection")
        == "command_injection"
    )
    assert usaf.map_rule_to_kind("java-path-traversal") == "path_traversal"
    assert usaf.map_rule_to_kind("custom-foo-ssrf-bar") == "ssrf"
    assert usaf.map_rule_to_kind("python-stack-trace-exposure") == "unmapped"
    assert usaf.map_rule_to_kind("unknown-rule", cwe="918") == "ssrf"


def test_uri_to_relpath_file_uri(tmp_path):
    usaf = load_adapter()
    app = tmp_path / "tools" / "fetcher.py"
    app.parent.mkdir(parents=True)
    app.write_text("x\n", encoding="utf-8")
    uri = app.resolve().as_uri()
    assert usaf._uri_to_relpath(uri, tmp_path) == "tools/fetcher.py"


def test_language_not_supported(tmp_path):
    usaf = load_adapter()
    result = usaf.scan_with_metadata(tmp_path, "swift")
    assert result["findings"] == []
    assert result["skipReason"] == "language_not_supported"


def test_missing_env(tmp_path, monkeypatch):
    usaf = load_adapter()
    monkeypatch.delenv("USAF_CLI", raising=False)
    monkeypatch.delenv("USAF_RULES_JSON", raising=False)
    result = usaf.scan_with_metadata(tmp_path, "python")
    assert result["findings"] == []
    assert result["skipReason"] == "scanner_not_installed"


def test_scan_with_metadata_parses_sarif(monkeypatch, tmp_path):
    usaf = load_adapter()
    app = tmp_path / "tools" / "fetcher.py"
    app.parent.mkdir(parents=True)
    app.write_text("import requests\n", encoding="utf-8")

    monkeypatch.setenv("USAF_CLI", "/fake/usaf_cli")
    monkeypatch.setenv("USAF_RULES_JSON", str(tmp_path / "rules.json"))
    (tmp_path / "rules.json").write_text("{}", encoding="utf-8")

    def fake_run(command, capture_output, text, timeout):
        sarif_path = Path(command[2])
        payload = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "python-ssrf",
                            "level": "error",
                            "message": {"text": "SSRF"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": app.resolve().as_uri()
                                        },
                                        "region": {
                                            "startLine": 21,
                                            "endLine": 30,
                                        },
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        sarif_path.write_text(json.dumps(payload), encoding="utf-8")
        return SimpleNamespace(stdout="ok", stderr="", returncode=0)

    monkeypatch.setattr(usaf.subprocess, "run", fake_run)
    result = usaf.scan_with_metadata(tmp_path, "python")

    assert result["skipReason"] is None
    assert result["exitCode"] == 0
    assert result["commandInvocation"][0] == "/fake/usaf_cli"
    assert "--language" in result["commandInvocation"]
    assert (
        result["commandInvocation"][
            result["commandInvocation"].index("--language") + 1
        ]
        == "python"
    )
    assert result["findings"] == [
        {
            "ruleId": "python-ssrf",
            "mappedKind": "ssrf",
            "path": "tools/fetcher.py",
            "startLine": 21,
            "endLine": 30,
            "severity": "high",
            "message": "SSRF",
        }
    ]


def test_typescript_maps_to_javascript_language_flag(monkeypatch, tmp_path):
    usaf = load_adapter()
    monkeypatch.setenv("USAF_CLI", "/fake/usaf_cli")
    monkeypatch.setenv("USAF_RULES_JSON", str(tmp_path / "rules.json"))
    (tmp_path / "rules.json").write_text("{}", encoding="utf-8")

    seen = {}

    def fake_run(command, capture_output, text, timeout):
        seen["command"] = command
        Path(command[2]).write_text(
            json.dumps({"runs": [{"results": []}]}), encoding="utf-8"
        )
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(usaf.subprocess, "run", fake_run)
    usaf.scan_with_metadata(tmp_path, "typescript")
    cmd = seen["command"]
    assert cmd[cmd.index("--language") + 1] == "javascript"
