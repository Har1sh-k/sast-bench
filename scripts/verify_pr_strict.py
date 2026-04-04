"""Strict verifier for real_world_disclosed PR simulation data.

Checks every real_world_disclosed case against:
1. Snapshot is at realWorld.vulnerableCommit
2. headCommit contains the exact annotated vulnerable slice
3. baseCommit does NOT contain the exact annotated vulnerable slice
4. fixCommit does NOT contain the exact annotated vulnerable slice
5. For multi-region cases, all mustDetect regions must satisfy the rules

Usage:
    python scripts/verify_pr_strict.py
    python scripts/verify_pr_strict.py --case-id SB-PY-RW-001
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "cases" / "full" / "real_world_disclosed"
REPOS_DIR = REPO_ROOT / ".repos"


def git_show(repo: Path, commit: str, filepath: str) -> str | None:
    r = subprocess.run(
        ["git", "show", f"{commit}:{filepath}"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    return r.stdout if r.returncode == 0 else None


def get_snapshot_commit(repo: Path) -> str | None:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def get_vuln_slice(repo: Path, commit: str, filepath: str, start: int, end: int) -> str | None:
    content = git_show(repo, commit, filepath)
    if not content:
        return None
    lines = content.split("\n")
    if end > len(lines):
        return None
    return "\n".join(lines[start - 1 : end])


def verify_case(case_path: Path) -> dict:
    with open(case_path) as f:
        c = json.load(f)

    rw = c["realWorld"]
    pr = c.get("prSimulation", {})
    cid = c.get("caseId", case_path.parent.name)
    vc = rw["vulnerableCommit"]
    fix = rw.get("fixCommit", "")
    base = pr.get("baseCommit", "")
    head = pr.get("headCommit", vc)
    repo = REPOS_DIR / f"{rw['repo'].replace('/', '_')}__{vc[:8]}"

    result = {
        "caseId": cid,
        "snap_ok": False,
        "head_ok": True,
        "base_ok": True,
        "fix_ok": True,
        "details": [],
    }

    if not repo.exists():
        result["details"].append("repo directory missing")
        return result

    # 1. Snapshot at vulnerableCommit
    snap = get_snapshot_commit(repo)
    result["snap_ok"] = bool(snap and snap.startswith(vc[:8]))
    if not result["snap_ok"]:
        result["details"].append(f"snapshot at {snap[:8] if snap else 'N/A'}, expected {vc[:8]}")

    must = set(c.get("expectedOutcome", {}).get("mustDetectRegionIds", []))
    regions = [r for r in c.get("regions", []) if r["id"] in must]

    for region in regions:
        fp = region["path"]
        sl, el = region["startLine"], region["endLine"]
        rid = region["id"]

        vuln_text = get_vuln_slice(repo, vc, fp, sl, el)
        if not vuln_text:
            result["details"].append(f"{rid}: cannot read vuln slice at vulnerableCommit")
            result["head_ok"] = False
            continue

        # 2. Head must contain vuln text
        hc = git_show(repo, head, fp)
        if not hc or vuln_text not in hc:
            result["head_ok"] = False
            result["details"].append(f"{rid}: head {head[:8]} missing vuln slice")

        # 3. Base must NOT contain vuln text
        bc = git_show(repo, base, fp)
        if bc and vuln_text in bc:
            result["base_ok"] = False
            result["details"].append(f"{rid}: base {base[:8]} contains vuln slice")

        # 4. Fix must NOT contain vuln text
        if fix:
            fc = git_show(repo, fix, fp)
            if fc and vuln_text in fc:
                result["fix_ok"] = False
                result["details"].append(f"{rid}: fix {fix[:8]} still contains vuln slice")

    result["strict"] = all([
        result["snap_ok"],
        result["head_ok"],
        result["base_ok"],
        result["fix_ok"],
    ])
    return result


def main():
    parser = argparse.ArgumentParser(description="Strict PR simulation verifier")
    parser.add_argument("--case-id", help="Verify a single case")
    args = parser.parse_args()

    case_files = sorted(CASES_DIR.rglob("case.json"))
    if args.case_id:
        case_files = [
            cf for cf in case_files
            if args.case_id in str(cf)
        ]

    results = [verify_case(cf) for cf in case_files]
    total = len(results)
    strict_count = sum(1 for r in results if r["strict"])
    snap_count = sum(1 for r in results if r["snap_ok"])
    head_count = sum(1 for r in results if r["head_ok"])
    base_count = sum(1 for r in results if r["base_ok"])
    fix_count = sum(1 for r in results if r["fix_ok"])

    print(f"Strict pass: {strict_count}/{total}")
    print(f"  Snapshots at vulnerableCommit: {snap_count}/{total}")
    print(f"  Head has vuln:                 {head_count}/{total}")
    print(f"  Base clean:                    {base_count}/{total}")
    print(f"  Fix clean:                     {fix_count}/{total}")

    for r in results:
        if not r["strict"]:
            print(f"\nFAIL {r['caseId']}:")
            for d in r["details"]:
                print(f"  {d}")

    return 0 if strict_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
