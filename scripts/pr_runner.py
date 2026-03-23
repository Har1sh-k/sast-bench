"""SASTbench PR mode runner.

Implements PR simulation benchmark: scans base and head trees,
computes diff, synthesizes review findings, and scores whether
introduced vulnerabilities are detected.

Usage (via run.py):
    python scripts/run.py --scanner semgrep --mode pr --track core
"""

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from scoring import Finding
from pr_scoring import (
    PRCaseScoring,
    synthesize_review_findings,
    score_pr_case,
    compute_pr_summary,
)
from run import (
    REPO_ROOT,
    CASES_DIR,
    find_cases,
    load_adapter,
    normalize_relpath,
    write_artifact,
)

B = "\033[1;36m[SASTbench]\033[0m"
SEP = "\033[2m" + "-" * 45 + "\033[0m"


def _has_pr_simulation(case: dict) -> bool:
    """Check if a case has prSimulation metadata."""
    return "prSimulation" in case


def _materialize_vendored(case_dir: Path, case: dict, tmp_root: Path) -> tuple[Path, Path]:
    """Materialize base and head trees for a vendored_base case.

    Copies both trees into a temp directory for symmetric scanning.
    Returns (base_scan_root, head_scan_root).
    """
    pr_sim = case["prSimulation"]
    base_src = case_dir / pr_sim["baseRoot"]
    head_src = case_dir / case["files"]["root"]

    base_dst = tmp_root / "base"
    head_dst = tmp_root / "head"

    shutil.copytree(base_src, base_dst)
    shutil.copytree(head_src, head_dst)

    return base_dst, head_dst


def _materialize_git_commits(case_dir: Path, case: dict, tmp_root: Path) -> tuple[Path, Path]:
    """Materialize base and head trees for a git_commit_pair case.

    Uses git worktrees from the repo snapshot to check out both commits.
    Returns (base_scan_root, head_scan_root).
    """
    pr_sim = case["prSimulation"]
    real_world = case["realWorld"]

    base_commit = pr_sim["baseCommit"]
    head_commit = pr_sim.get("headCommit", real_world["vulnerableCommit"])

    # Resolve the repo root from the case's files.root
    repo_root = (case_dir / case["files"]["root"]).resolve()

    base_dst = tmp_root / "base"
    head_dst = tmp_root / "head"

    # Use git archive to extract each commit into a temp dir
    for commit, dst in [(base_commit, base_dst), (head_commit, head_dst)]:
        dst.mkdir(parents=True)
        result = subprocess.run(
            ["git", "archive", "--format=tar", commit],
            cwd=str(repo_root),
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git archive failed for {commit}: {result.stderr.decode()}"
            )
        # Extract tar into destination
        subprocess.run(
            ["tar", "xf", "-"],
            input=result.stdout,
            cwd=str(dst),
            timeout=120,
            check=True,
        )

    return base_dst, head_dst


def _compute_changed_files(base_root: Path, head_root: Path) -> list[str]:
    """Compute list of changed files between base and head trees.

    Uses simple file comparison for vendored trees.
    """
    changed: list[str] = []

    # Gather all relative paths from both trees
    base_files: set[str] = set()
    head_files: set[str] = set()

    for p in base_root.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(base_root)).replace("\\", "/")
            base_files.add(rel)

    for p in head_root.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(head_root)).replace("\\", "/")
            head_files.add(rel)

    # New files in head
    for f in sorted(head_files - base_files):
        changed.append(f)

    # Deleted files
    for f in sorted(base_files - head_files):
        changed.append(f)

    # Modified files (present in both, content differs)
    for f in sorted(base_files & head_files):
        base_content = (base_root / f).read_bytes()
        head_content = (head_root / f).read_bytes()
        if base_content != head_content:
            changed.append(f)

    return changed


def _scan_tree(adapter, scan_root: Path, language: str) -> tuple[list[Finding], dict]:
    """Scan a tree using the adapter and return (findings, scan_meta)."""
    scan_meta = {
        "findings": [],
        "commandInvocation": None,
        "exitCode": None,
        "rawStdout": "",
        "rawStderr": "",
        "skipReason": None,
    }

    try:
        if hasattr(adapter, "scan_with_metadata"):
            scan_meta = adapter.scan_with_metadata(scan_root, language)
        else:
            scan_meta["findings"] = adapter.scan(scan_root, language)
    except Exception as e:
        scan_meta["rawStderr"] = str(e)
        scan_meta["skipReason"] = "adapter_error"

    findings = []
    for rf in scan_meta["findings"]:
        findings.append(Finding(
            rule_id=rf["ruleId"],
            mapped_kind=rf["mappedKind"],
            path=rf["path"],
            start_line=rf["startLine"],
            end_line=rf["endLine"],
            severity=rf.get("severity", ""),
            message=rf.get("message", ""),
        ))

    return findings, scan_meta


def _finding_to_dict(f: Finding) -> dict:
    """Convert a Finding to a result dict."""
    d = {
        "ruleId": f.rule_id,
        "mappedKind": f.mapped_kind,
        "path": f.path,
        "startLine": f.start_line,
        "endLine": f.end_line,
    }
    if f.severity:
        d["severity"] = f.severity
    if f.message:
        d["message"] = f.message
    return d


def _format_pr_status(scoring: PRCaseScoring, skip_reason: str | None) -> str:
    """Format a concise one-line PR status."""
    if skip_reason:
        return f"SKIP | skip={skip_reason}"

    if scoring.introduced_targets_total == 0:
        return "NO TARGETS"

    if scoring.introduced_targets_detected == scoring.introduced_targets_total:
        outcome = "INTRODUCED VULN DETECTED"
    elif scoring.introduced_targets_detected > 0:
        outcome = "PARTIAL DETECTION"
    else:
        outcome = "INTRODUCED VULN MISSED"

    parts = [outcome]
    if scoring.review_noise:
        parts.append(f"review-noise={scoring.review_noise}")
    if scoring.capability_noise:
        parts.append(f"cap-noise={scoring.capability_noise}")
    return " | ".join(parts)


def _print_pr_verbose(
    base_findings: list[Finding],
    head_findings: list[Finding],
    review_findings: list[Finding],
    changed_files: list[str],
    prefix: str,
) -> None:
    """Print detailed PR findings in verbose mode."""
    print(f"{prefix}   changed files: {len(changed_files)}")
    for cf in changed_files[:10]:
        print(f"{prefix}     {cf}")
    if len(changed_files) > 10:
        print(f"{prefix}     ... and {len(changed_files) - 10} more")

    print(f"{prefix}   base findings: {len(base_findings)}")
    print(f"{prefix}   head findings: {len(head_findings)}")
    print(f"{prefix}   review (new-in-head) findings: {len(review_findings)}")

    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"
    for rf in review_findings:
        print(f"{prefix}     {GREEN}[REVIEW]{RESET} {rf.path}:{rf.start_line}-{rf.end_line}")
        print(f"{prefix}       kind={rf.mapped_kind}  rule={rf.rule_id}")
        if rf.message:
            print(f"{prefix}       {rf.message}")


def run_pr_benchmark(
    scanner_name: str,
    track: str,
    output_path: Path,
    case_type: str | None = None,
    case_id: str | None = None,
    verbose: bool = False,
    started_at: datetime | None = None,
) -> int:
    """Run PR simulation benchmark."""
    started_at = started_at or datetime.now(timezone.utc)
    output_dir = output_path.parent
    artifacts_root = output_dir / f"{output_path.stem}_artifacts"

    adapter = load_adapter(scanner_name)
    adapter_version = getattr(adapter, "ADAPTER_VERSION", "1.0.0")
    scanner_version = adapter.get_version()

    all_cases = find_cases(track, case_type, case_id)
    pr_cases = [(d, c) for d, c in all_cases if _has_pr_simulation(c)]

    if not pr_cases:
        print(f"{B} No PR-capable cases found (need prSimulation metadata).")
        skipped_count = len(all_cases)
        if skipped_count:
            print(f"{B} {skipped_count} case(s) skipped (no prSimulation).")
        return 1

    skipped = len(all_cases) - len(pr_cases)
    print(f"{B} Running SASTbench PR mode ({track} track) with {scanner_name}")
    print(f"{B} Found {len(pr_cases)} PR-capable cases")
    if skipped:
        print(f"{B} Skipping {skipped} cases without prSimulation")
    print()

    case_results = []
    all_scorings: list[PRCaseScoring] = []

    for case_dir, case in pr_cases:
        current_case_id = case["id"]
        pr_sim = case["prSimulation"]
        pr_mode = pr_sim["mode"]

        print(f"{B} PR scanning {current_case_id} (mode={pr_mode})...")
        print(f"{SEP}", flush=True)

        skip_reason = None
        base_findings: list[Finding] = []
        head_findings: list[Finding] = []
        review_findings: list[Finding] = []
        changed_files: list[str] = []
        base_meta: dict = {}
        head_meta: dict = {}

        tmp_dir = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix=f"sastbench_pr_{current_case_id}_"))

            # Materialize trees
            if pr_mode == "vendored_base":
                base_root, head_root = _materialize_vendored(case_dir, case, tmp_dir)
            elif pr_mode == "git_commit_pair":
                base_root, head_root = _materialize_git_commits(case_dir, case, tmp_dir)
            else:
                skip_reason = f"unknown_pr_mode:{pr_mode}"
                base_root = head_root = tmp_dir

            if not skip_reason:
                # Compute changed files
                changed_files = _compute_changed_files(base_root, head_root)

                # Scan base
                print(f"{B}   Scanning base tree...", flush=True)
                base_findings, base_meta = _scan_tree(adapter, base_root, case["language"])

                # Scan head
                print(f"{B}   Scanning head tree...", flush=True)
                head_findings, head_meta = _scan_tree(adapter, head_root, case["language"])

                if base_meta.get("skipReason") or head_meta.get("skipReason"):
                    skip_reason = base_meta.get("skipReason") or head_meta.get("skipReason")

                if not skip_reason:
                    # Synthesize review findings
                    review_findings = synthesize_review_findings(base_findings, head_findings)

        except Exception as e:
            print(f"{B} ERROR: {e}")
            skip_reason = f"materialization_error"

        finally:
            if tmp_dir and tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

        # Score
        if not skip_reason:
            pr_scoring = score_pr_case(case, review_findings)
        else:
            pr_scoring = PRCaseScoring(
                case_id=current_case_id,
                introduced_targets_total=len(
                    case["expectedOutcome"].get("mustDetectRegionIds", [])
                ),
            )

        all_scorings.append(pr_scoring)

        # Write artifacts
        artifact_info = {
            "commandInvocation": head_meta.get("commandInvocation") if head_meta else None,
            "exitCode": head_meta.get("exitCode") if head_meta else None,
            "rawStdoutPath": None,
            "rawStderrPath": None,
            "skipReason": skip_reason,
        }

        raw_stdout = (head_meta.get("rawStdout", "") if head_meta else "")
        raw_stderr = (head_meta.get("rawStderr", "") if head_meta else "")
        if raw_stdout or raw_stderr:
            case_artifact_dir = artifacts_root / current_case_id
            stdout_path = case_artifact_dir / "scanner.stdout.txt"
            stderr_path = case_artifact_dir / "scanner.stderr.txt"
            write_artifact(stdout_path, raw_stdout)
            write_artifact(stderr_path, raw_stderr)
            artifact_info["rawStdoutPath"] = normalize_relpath(stdout_path, output_dir)
            artifact_info["rawStderrPath"] = normalize_relpath(stderr_path, output_dir)

        # Build case result
        # Use head findings as the primary finding list for benchmark compatibility
        from scoring import classify_findings
        benchmark_scoring, classifications = classify_findings(case, head_findings)

        finding_dicts = []
        for f, fc in zip(head_findings, classifications):
            finding_dicts.append({
                "ruleId": f.rule_id,
                "mappedKind": f.mapped_kind,
                "path": f.path,
                "startLine": f.start_line,
                "endLine": f.end_line,
                "severity": f.severity,
                "message": f.message,
                "matchedRegionId": fc.matched_region_id,
                "classification": fc.classification,
            })

        case_result = {
            "caseId": current_case_id,
            "caseTrack": case["track"],
            "caseType": case["caseType"],
            "language": case["language"],
            "findings": finding_dicts,
            "scoring": {
                "truePositives": benchmark_scoring.true_positives,
                "falseNegatives": benchmark_scoring.false_negatives,
                "falsePositives": benchmark_scoring.false_positives,
                "capabilityFalsePositives": benchmark_scoring.capability_false_positives,
            },
            "artifacts": artifact_info,
            "prContext": {
                "changedFiles": changed_files,
                "baselineFindings": [_finding_to_dict(f) for f in base_findings],
                "headFindings": [_finding_to_dict(f) for f in head_findings],
                "reviewFindings": [_finding_to_dict(f) for f in review_findings],
            },
            "prScoring": {
                "introducedTargetsDetected": pr_scoring.introduced_targets_detected,
                "introducedTargetsTotal": pr_scoring.introduced_targets_total,
                "introducedTargetHitRate": pr_scoring.introduced_target_hit_rate,
                "reviewNoise": pr_scoring.review_noise,
                "capabilityNoise": pr_scoring.capability_noise,
            },
        }
        case_results.append(case_result)

        # Print status
        result_str = _format_pr_status(pr_scoring, skip_reason)
        print(f"{SEP}")
        print(f"{B} {current_case_id} => {result_str}")
        if verbose:
            _print_pr_verbose(base_findings, head_findings, review_findings, changed_files, B)
        print()

    # Compute summary
    pr_summary = compute_pr_summary(all_scorings, skipped)

    # Also compute benchmark summary for compatibility
    from scoring import compute_summary, CaseScoring
    benchmark_scorings = []
    benchmark_cases = []
    for cr in case_results:
        s = cr["scoring"]
        benchmark_scorings.append(CaseScoring(
            case_id=cr["caseId"],
            case_type=cr["caseType"],
            true_positives=s["truePositives"],
            false_negatives=s["falseNegatives"],
            false_positives=s["falsePositives"],
            capability_false_positives=s["capabilityFalsePositives"],
        ))
        # Find matching case dict
        for _, c in pr_cases:
            if c["id"] == cr["caseId"]:
                benchmark_cases.append(c)
                break

    benchmark_summary = compute_summary(benchmark_scorings, benchmark_cases)

    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "mode": "pr",
        "scanner": {
            "name": scanner_name,
            "version": scanner_version,
            "adapter": adapter_version,
        },
        "track": track,
        "timestamp": started_at.isoformat(),
        "caseResults": case_results,
        "summary": {
            "recall": benchmark_summary.recall,
            "precision": benchmark_summary.precision,
            "capabilityFpRate": benchmark_summary.capability_fp_rate,
            "mixedIntentAccuracy": benchmark_summary.mixed_intent_accuracy,
            "agenticScore": benchmark_summary.agentic_score,
        },
        "prSummary": {
            "introducedTargetHitRate": pr_summary.introduced_target_hit_rate,
            "totalReviewNoise": pr_summary.total_review_noise,
            "totalCapabilityNoise": pr_summary.total_capability_noise,
            "casesEvaluated": pr_summary.cases_evaluated,
            "casesSkipped": pr_summary.cases_skipped,
        },
    }

    # Print PR summary
    print(f"\n{B} {'='*50}")
    print(f"{B} PR Results - {scanner_name} v{scanner_version} ({track} track)")
    print(f"{B} {'='*50}")
    print(f"{B}   Introduced Target Hit Rate: {pr_summary.introduced_target_hit_rate:.1%}")
    print(f"{B}   Review Noise:               {pr_summary.total_review_noise}")
    print(f"{B}   Capability Noise:           {pr_summary.total_capability_noise}")
    print(f"{B}   Cases Evaluated:            {pr_summary.cases_evaluated}")
    if pr_summary.cases_skipped:
        print(f"{B}   Cases Skipped:              {pr_summary.cases_skipped}")

    if verbose:
        print(f"{B}   ---")
        print(f"{B}   Benchmark Recall:           {benchmark_summary.recall:.1%}")
        print(f"{B}   Benchmark Precision:        {benchmark_summary.precision:.1%}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"{B} Results written to {output_path}")
    print(f"{B} Raw artifacts written to {artifacts_root}")
    return 0
