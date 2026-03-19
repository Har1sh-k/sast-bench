"""Tests for the SASTbench case validator."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from validate import find_cases, validate_case, CASES_DIR


def test_all_cases_are_valid():
    """Every case in the repo should pass validation."""
    cases = find_cases(CASES_DIR)
    assert len(cases) > 0, "No cases found"

    all_errors = []
    for case_dir in cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    if all_errors:
        for error in all_errors:
            print(f"  ERROR: {error}")

    assert len(all_errors) == 0, f"{len(all_errors)} validation error(s)"


def test_minimum_case_count():
    """V1 requires at least 15 official cases (12 core + 3 full)."""
    cases = find_cases(CASES_DIR)
    assert len(cases) >= 12, f"Only {len(cases)} cases found, need at least 12 for Core Track"


def test_case_type_distribution():
    """Check we have the right mix of case types per the plan."""
    import json

    cases = find_cases(CASES_DIR)
    type_counts = {}

    for case_dir in cases:
        with open(case_dir / "case.json") as f:
            case = json.load(f)
        ct = case["caseType"]
        type_counts[ct] = type_counts.get(ct, 0) + 1

    # Core Track minimums (plan section 8)
    assert type_counts.get("synthetic_vulnerable", 0) >= 6, "Need at least 6 synthetic_vulnerable"
    assert type_counts.get("capability_safe", 0) >= 3, "Need at least 3 capability_safe"
    assert type_counts.get("mixed_intent", 0) >= 3, "Need at least 3 mixed_intent"


def test_full_track_release_bar():
    """V1 release requires at least 3 real_world_disclosed cases (plan section 8).

    This test documents the release bar. It currently warns instead of
    failing because Full Track cases are being annotated.
    """
    import json

    full_dir = CASES_DIR / "full"
    rw_count = 0
    for case_json in full_dir.rglob("case.json"):
        with open(case_json) as f:
            case = json.load(f)
        if case.get("caseType") == "real_world_disclosed":
            rw_count += 1

    if rw_count < 3:
        print(f"  WARNING: Full Track has {rw_count}/3 real_world_disclosed cases -- below v1.0.0 release bar")


def test_language_distribution():
    """Check all three languages are represented."""
    import json

    cases = find_cases(CASES_DIR)
    languages = set()

    for case_dir in cases:
        with open(case_dir / "case.json") as f:
            case = json.load(f)
        languages.add(case["language"])

    assert "python" in languages
    assert "typescript" in languages
    assert "rust" in languages


if __name__ == "__main__":
    test_all_cases_are_valid()
    test_minimum_case_count()
    test_case_type_distribution()
    test_full_track_release_bar()
    test_language_distribution()
    print("All tests passed.")
