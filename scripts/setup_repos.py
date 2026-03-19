"""SASTbench Full Track repo setup.

Clones and pins real-world repositories at their vulnerable commits
for Full Track benchmark cases.

Usage:
    python scripts/setup_repos.py
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_CASES_DIR = REPO_ROOT / "cases" / "full"
REPOS_DIR = REPO_ROOT / ".repos"


def find_real_world_cases() -> list[tuple[Path, dict]]:
    """Find all real_world_disclosed cases."""
    cases = []
    for case_json in sorted(FULL_CASES_DIR.rglob("case.json")):
        with open(case_json) as f:
            case = json.load(f)
        if case.get("caseType") == "real_world_disclosed":
            cases.append((case_json.parent, case))
    return cases


def clone_and_pin(repo: str, commit: str, target_dir: Path) -> bool:
    """Clone a repo and checkout a specific commit."""
    if target_dir.exists():
        print(f"    Already exists: {target_dir}")
        return True

    target_dir.parent.mkdir(parents=True, exist_ok=True)

    print(f"    Cloning {repo}...", end=" ", flush=True)
    result = subprocess.run(
        ["git", "clone", "--no-checkout", f"https://github.com/{repo}.git", str(target_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        print(f"FAILED: {result.stderr.strip()}")
        return False

    print(f"checking out {commit[:8]}...", end=" ", flush=True)
    result = subprocess.run(
        ["git", "-C", str(target_dir), "checkout", commit],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        print(f"FAILED: {result.stderr.strip()}")
        return False

    print("OK")
    return True


def main() -> int:
    cases = find_real_world_cases()

    if not cases:
        print("No real_world_disclosed cases found in Full Track.")
        print("Full Track cases will be added as they are annotated.")
        return 0

    print(f"Setting up {len(cases)} real-world repos\n")

    success = 0
    for case_dir, case in cases:
        rw = case.get("realWorld", {})
        repo = rw.get("repo", "")
        commit = rw.get("vulnerableCommit", "")

        if not repo or not commit:
            print(f"  [{case['id']}] Missing repo or commit metadata, skipping")
            continue

        print(f"  [{case['id']}] {repo} @ {commit[:8]}")
        target = REPOS_DIR / repo.replace("/", "_")

        if clone_and_pin(repo, commit, target):
            success += 1

    print(f"\n{success}/{len(cases)} repos ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
