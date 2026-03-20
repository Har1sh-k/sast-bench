"""Tests for the dual-detail reporting mode (default vs verbose)."""

import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from run import _case_outcome, _format_default_status, _print_verbose_findings
from report import render_finding_card, render_case_deep_section, generate_report


# ---------------------------------------------------------------------------
# _case_outcome
# ---------------------------------------------------------------------------

@dataclass
class _FakeScoring:
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    capability_false_positives: int = 0


def test_outcome_hit():
    assert _case_outcome(_FakeScoring(true_positives=1), None) == "HIT"


def test_outcome_hit_noisy_fp():
    assert _case_outcome(_FakeScoring(true_positives=1, false_positives=3), None) == "HIT (noisy)"


def test_outcome_hit_noisy_capfp():
    assert _case_outcome(_FakeScoring(true_positives=1, capability_false_positives=1), None) == "HIT (noisy)"


def test_outcome_miss():
    assert _case_outcome(_FakeScoring(false_negatives=1), None) == "MISS"


def test_outcome_clean():
    assert _case_outcome(_FakeScoring(), None) == "CLEAN"


def test_outcome_noisy_fp_only():
    assert _case_outcome(_FakeScoring(false_positives=2), None) == "NOISY"


def test_outcome_noisy_capfp_only():
    """CapFP-only cases should be NOISY, not CLEAN."""
    assert _case_outcome(_FakeScoring(capability_false_positives=1), None) == "NOISY"


def test_outcome_skip():
    assert _case_outcome(_FakeScoring(), "adapter_error") == "SKIP"


# ---------------------------------------------------------------------------
# _format_default_status
# ---------------------------------------------------------------------------

def test_format_hit_clean():
    s = _format_default_status(_FakeScoring(true_positives=1), None)
    assert s == "HIT"


def test_format_miss_with_fn():
    s = _format_default_status(_FakeScoring(false_negatives=1), None)
    assert "MISS" in s
    assert "FN=1" in s


def test_format_hit_with_fp_and_capfp():
    s = _format_default_status(
        _FakeScoring(true_positives=1, false_positives=2, capability_false_positives=1), None
    )
    assert "HIT" in s
    assert "FP=2" in s
    assert "CapFP=1" in s


def test_format_skip():
    s = _format_default_status(_FakeScoring(), "timeout")
    assert "SKIP" in s
    assert "skip=timeout" in s


# ---------------------------------------------------------------------------
# render_finding_card (HTML report)
# ---------------------------------------------------------------------------

def test_finding_card_tp():
    card = render_finding_card({
        "classification": "true_positive",
        "path": "tools/fetcher.py",
        "startLine": 10,
        "endLine": 20,
        "mappedKind": "ssrf",
        "ruleId": "test-rule",
        "severity": "high",
        "message": "SSRF found",
        "matchedRegionId": "R1",
    })
    assert 'class="finding tp"' in card
    assert "TP" in card
    assert "tools/fetcher.py" in card
    assert "R1" in card


def test_finding_card_fp():
    card = render_finding_card({
        "classification": "false_positive",
        "path": "agent/router.py",
        "startLine": 5,
        "endLine": 5,
        "mappedKind": "ssrf",
        "ruleId": "test-rule",
        "severity": "low",
        "message": "",
    })
    assert 'class="finding fp"' in card
    assert "FP" in card


def test_finding_card_capfp():
    card = render_finding_card({
        "classification": "capability_false_positive",
        "path": "tools/runner.py",
        "startLine": 1,
        "endLine": 50,
        "mappedKind": "command_injection",
        "ruleId": "test-rule",
        "severity": "high",
        "message": "Subprocess call",
        "matchedRegionId": "R1",
    })
    assert 'class="finding cap-fp"' in card
    assert "CAP FP" in card


# ---------------------------------------------------------------------------
# render_case_deep_section
# ---------------------------------------------------------------------------

def test_deep_section_with_findings():
    section = render_case_deep_section({
        "caseId": "SB-PY-SV-001",
        "scoring": {"truePositives": 1, "falseNegatives": 0, "falsePositives": 2, "capabilityFalsePositives": 0},
        "findings": [
            {"classification": "true_positive", "path": "a.py", "startLine": 1, "endLine": 1,
             "mappedKind": "ssrf", "ruleId": "r1", "severity": "high", "message": "TP"},
            {"classification": "false_positive", "path": "b.py", "startLine": 1, "endLine": 1,
             "mappedKind": "ssrf", "ruleId": "r2", "severity": "low", "message": "FP1"},
            {"classification": "false_positive", "path": "c.py", "startLine": 1, "endLine": 1,
             "mappedKind": "ssrf", "ruleId": "r3", "severity": "low", "message": "FP2"},
        ],
    })
    assert "<details>" in section
    assert "SB-PY-SV-001" in section
    assert "3 findings" in section
    assert "1 TP" in section
    assert "2 FP" in section


def test_deep_section_no_findings():
    """Cases with zero findings still get a section in deep mode."""
    section = render_case_deep_section({
        "caseId": "SB-RS-SV-002",
        "scoring": {"truePositives": 0, "falseNegatives": 1, "falsePositives": 0, "capabilityFalsePositives": 0},
        "findings": [],
    })
    assert "<details>" in section
    assert "SB-RS-SV-002" in section
    assert "0 findings" in section
    assert "1 FN" in section
    assert "No findings from scanner" in section


# ---------------------------------------------------------------------------
# generate_report deep vs default
# ---------------------------------------------------------------------------

def test_generate_report_default_has_no_deep_section(tmp_path):
    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "scanner": {"name": "test", "version": "1.0", "adapter": "1.0"},
        "track": "core",
        "timestamp": "2026-01-01T00:00:00Z",
        "caseResults": [{
            "caseId": "SB-PY-SV-001", "caseTrack": "core", "caseType": "synthetic_vulnerable",
            "language": "python",
            "findings": [{"classification": "true_positive", "path": "a.py", "startLine": 1,
                          "endLine": 1, "mappedKind": "ssrf", "ruleId": "r", "severity": "high", "message": "x"}],
            "scoring": {"truePositives": 1, "falseNegatives": 0, "falsePositives": 0, "capabilityFalsePositives": 0},
            "artifacts": {"commandInvocation": None, "exitCode": None, "rawStdoutPath": None, "rawStderrPath": None, "skipReason": None},
        }],
        "summary": {"recall": 1.0, "precision": 1.0, "capabilityFpRate": 0.0, "mixedIntentAccuracy": 0.0, "agenticScore": 0.0},
    }
    html_out = generate_report(results, tmp_path, tmp_path, deep=False)
    assert "Finding-Level Audit Trail" not in html_out


def test_generate_report_deep_has_audit_section(tmp_path):
    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "scanner": {"name": "test", "version": "1.0", "adapter": "1.0"},
        "track": "core",
        "timestamp": "2026-01-01T00:00:00Z",
        "caseResults": [{
            "caseId": "SB-PY-SV-001", "caseTrack": "core", "caseType": "synthetic_vulnerable",
            "language": "python",
            "findings": [{"classification": "true_positive", "path": "a.py", "startLine": 1,
                          "endLine": 1, "mappedKind": "ssrf", "ruleId": "r", "severity": "high", "message": "x"}],
            "scoring": {"truePositives": 1, "falseNegatives": 0, "falsePositives": 0, "capabilityFalsePositives": 0},
            "artifacts": {"commandInvocation": None, "exitCode": None, "rawStdoutPath": None, "rawStderrPath": None, "skipReason": None},
        }],
        "summary": {"recall": 1.0, "precision": 1.0, "capabilityFpRate": 0.0, "mixedIntentAccuracy": 0.0, "agenticScore": 0.0},
    }
    html_out = generate_report(results, tmp_path, tmp_path, deep=True)
    assert "Finding-Level Audit Trail" in html_out
    assert "SB-PY-SV-001" in html_out
    assert "class=\"finding tp\"" in html_out
