"""SASTbench runner.

Runs a scanner adapter against benchmark cases and produces
normalized results in the official JSON format.

Usage:
    python scripts/run.py --scanner semgrep --track core
    python scripts/run.py --scanner bandit --track core --output results.json
"""

import argparse
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scoring import Finding, classify_findings, compute_summary

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "cases"
ADAPTERS_DIR = REPO_ROOT / "adapters"


def find_cases(track: str) -> list[tuple[Path, dict]]:
    """Find all cases for the given track."""
    cases = []

    if track == "core":
        search_dirs = [CASES_DIR / "core"]
    elif track == "full":
        search_dirs = [CASES_DIR / "core", CASES_DIR / "full"]
    else:
        print(f"Unknown track: {track}")
        sys.exit(1)

    for search_dir in search_dirs:
        for case_json in sorted(search_dir.rglob("case.json")):
            with open(case_json) as f:
                case = json.load(f)
            cases.append((case_json.parent, case))

    return cases


def load_adapter(scanner_name: str):
    """Load a scanner adapter module."""
    adapter_dir = ADAPTERS_DIR / scanner_name
    if not adapter_dir.exists():
        print(f"Adapter not found: {scanner_name}")
        print(f"Available adapters: {[d.name for d in ADAPTERS_DIR.iterdir() if d.is_dir()]}")
        sys.exit(1)

    sys.path.insert(0, str(adapter_dir))
    try:
        adapter = importlib.import_module("adapter")
    except ImportError as e:
        print(f"Failed to load adapter for {scanner_name}: {e}")
        sys.exit(1)

    return adapter


def run_benchmark(scanner_name: str, track: str, output_path: Path | None) -> int:
    """Run the benchmark and produce results."""
    adapter = load_adapter(scanner_name)
    cases = find_cases(track)

    if not cases:
        print("No cases found.")
        return 1

    print(f"Running SASTbench ({track} track) with {scanner_name}")
    print(f"Found {len(cases)} cases\n")

    scanner_version = adapter.get_version()
    case_results = []
    all_scorings = []
    all_cases = []

    for case_dir, case in cases:
        case_id = case["id"]
        scan_root = case_dir / case["files"]["root"]

        print(f"  Scanning {case_id}...", end=" ", flush=True)

        try:
            raw_findings = adapter.scan(scan_root, case["language"])
        except Exception as e:
            print(f"ERROR: {e}")
            raw_findings = []

        # Convert adapter findings to Finding objects
        findings = []
        for rf in raw_findings:
            findings.append(Finding(
                rule_id=rf["ruleId"],
                mapped_kind=rf["mappedKind"],
                path=rf["path"],
                start_line=rf["startLine"],
                end_line=rf["endLine"],
                severity=rf.get("severity", ""),
                message=rf.get("message", ""),
            ))

        scoring = classify_findings(case, findings)
        all_scorings.append(scoring)
        all_cases.append(case)

        # Build per-case result
        finding_dicts = []
        for f in findings:
            finding_dicts.append({
                "ruleId": f.rule_id,
                "mappedKind": f.mapped_kind,
                "path": f.path,
                "startLine": f.start_line,
                "endLine": f.end_line,
                "severity": f.severity,
                "message": f.message,
                "matchedRegionId": None,
                "classification": "unmatched",
            })

        case_results.append({
            "caseId": case_id,
            "findings": finding_dicts,
            "scoring": {
                "truePositives": scoring.true_positives,
                "falseNegatives": scoring.false_negatives,
                "falsePositives": scoring.false_positives,
                "capabilityFalsePositives": scoring.capability_false_positives,
            },
        })

        status_parts = []
        if scoring.true_positives:
            status_parts.append(f"TP={scoring.true_positives}")
        if scoring.false_negatives:
            status_parts.append(f"FN={scoring.false_negatives}")
        if scoring.capability_false_positives:
            status_parts.append(f"CapFP={scoring.capability_false_positives}")
        print(" | ".join(status_parts) if status_parts else "no findings")

    summary = compute_summary(all_scorings, all_cases)

    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "scanner": {
            "name": scanner_name,
            "version": scanner_version,
            "adapter": "1.0.0",
        },
        "track": track,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "caseResults": case_results,
        "summary": {
            "recall": summary.recall,
            "precision": summary.precision,
            "capabilityFpRate": summary.capability_fp_rate,
            "mixedIntentAccuracy": summary.mixed_intent_accuracy,
            "agenticScore": summary.agentic_score,
        },
    }

    print(f"\n{'='*50}")
    print(f"Results — {scanner_name} v{scanner_version} ({track} track)")
    print(f"{'='*50}")
    print(f"  Recall:                {summary.recall:.1%}")
    print(f"  Precision:             {summary.precision:.1%}")
    print(f"  Capability FP Rate:    {summary.capability_fp_rate:.1%}")
    print(f"  Mixed-Intent Accuracy: {summary.mixed_intent_accuracy:.1%}")
    print(f"  Agentic Score:         {summary.agentic_score:.1%}")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to {output_path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SASTbench runner")
    parser.add_argument("--scanner", required=True, help="Scanner adapter name")
    parser.add_argument("--track", default="core", choices=["core", "full"])
    parser.add_argument("--output", "-o", type=Path, help="Output JSON file path")
    args = parser.parse_args()

    return run_benchmark(args.scanner, args.track, args.output)


if __name__ == "__main__":
    sys.exit(main())
