"""Tests for setup_repos.py (no network access needed)."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, call

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import setup_repos


# ---------------------------------------------------------------------------
# repo_dir_name
# ---------------------------------------------------------------------------

def test_repo_dir_name_basic():
    assert setup_repos.repo_dir_name("owner/repo", "abcdef1234567890") == "owner_repo__abcdef12"


def test_repo_dir_name_short_commit():
    assert setup_repos.repo_dir_name("a/b", "12345678") == "a_b__12345678"


# ---------------------------------------------------------------------------
# has_checked_out_files
# ---------------------------------------------------------------------------

def test_has_checked_out_files_with_files(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "README.md").write_text("hi")
    assert setup_repos.has_checked_out_files(tmp_path) is True


def test_has_checked_out_files_only_git(tmp_path):
    (tmp_path / ".git").mkdir()
    assert setup_repos.has_checked_out_files(tmp_path) is False


def test_has_checked_out_files_empty(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert setup_repos.has_checked_out_files(empty) is False


def test_has_checked_out_files_missing(tmp_path):
    assert setup_repos.has_checked_out_files(tmp_path / "nope") is False


# ---------------------------------------------------------------------------
# disable_lfs
# ---------------------------------------------------------------------------

def test_disable_lfs_sets_config(tmp_path):
    """disable_lfs should run git config for all 4 LFS keys."""
    (tmp_path / ".git").mkdir()

    calls = []
    original_run_git = setup_repos.run_git

    def fake_run_git(args, *, timeout):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    with patch.object(setup_repos, "run_git", fake_run_git):
        setup_repos.disable_lfs(tmp_path)

    assert len(calls) == 4
    keys_set = [c[5] for c in calls]  # git -C <path> config --local <key> <val>
    assert "filter.lfs.clean" in keys_set
    assert "filter.lfs.smudge" in keys_set
    assert "filter.lfs.process" in keys_set
    assert "filter.lfs.required" in keys_set


# ---------------------------------------------------------------------------
# find_real_world_cases
# ---------------------------------------------------------------------------

def test_find_real_world_cases(tmp_path):
    case_dir = tmp_path / "cases" / "full" / "real_world_disclosed" / "SB-TEST-001"
    case_dir.mkdir(parents=True)
    case = {
        "id": "SB-TEST-001",
        "caseType": "real_world_disclosed",
        "realWorld": {"repo": "owner/repo", "vulnerableCommit": "abc123"},
    }
    (case_dir / "case.json").write_text(json.dumps(case))

    # Also add a non-RW case that should be excluded
    other_dir = tmp_path / "cases" / "full" / "other" / "SB-OTHER"
    other_dir.mkdir(parents=True)
    (other_dir / "case.json").write_text(json.dumps({"id": "SB-OTHER", "caseType": "synthetic_vulnerable"}))

    with patch.object(setup_repos, "FULL_CASES_DIR", tmp_path / "cases" / "full"):
        cases = setup_repos.find_real_world_cases()

    assert len(cases) == 1
    assert cases[0][1]["id"] == "SB-TEST-001"


# ---------------------------------------------------------------------------
# ensure_repo_checkout — existing repo, already ready
# ---------------------------------------------------------------------------

def test_ensure_checkout_already_ready(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".git").mkdir()
    (target / "file.py").write_text("code")

    disable_calls = []
    with patch.object(setup_repos, "disable_lfs", lambda d: disable_calls.append(d)):
        result = setup_repos.ensure_repo_checkout("o/r", "abc12345" * 5, target)

    assert result is True
    assert len(disable_calls) == 1  # LFS disabled even on ready repos


# ---------------------------------------------------------------------------
# ensure_repo_checkout — existing repo, needs repair
# ---------------------------------------------------------------------------

def test_ensure_checkout_repair(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".git").mkdir()
    # No files besides .git — needs repair

    commit = "abc12345" * 5

    git_calls = []

    def fake_run_git(args, *, timeout):
        git_calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    with patch.object(setup_repos, "run_git", fake_run_git):
        with patch.object(setup_repos, "disable_lfs"):
            result = setup_repos.ensure_repo_checkout("o/r", commit, target)

    assert result is True
    # Should have called fetch then checkout
    assert any("fetch" in c for c in git_calls)
    assert any("checkout" in c for c in git_calls)


# ---------------------------------------------------------------------------
# ensure_repo_checkout — fresh clone
# ---------------------------------------------------------------------------

def test_ensure_checkout_fresh_clone(tmp_path):
    target = tmp_path / "repo"  # does not exist

    commit = "abc12345" * 5
    git_calls = []
    disable_calls = []

    def fake_run_git(args, *, timeout):
        git_calls.append(args)
        if "clone" in args:
            # Simulate clone creating the dir
            target.mkdir(parents=True, exist_ok=True)
            (target / ".git").mkdir()
        return subprocess.CompletedProcess(args, 0)

    with patch.object(setup_repos, "run_git", fake_run_git):
        with patch.object(setup_repos, "disable_lfs", lambda d: disable_calls.append(d)):
            result = setup_repos.ensure_repo_checkout("o/r", commit, target)

    assert result is True
    assert any("clone" in c for c in git_calls)
    assert any("checkout" in c for c in git_calls)
    assert len(disable_calls) == 1  # LFS disabled after clone


# ---------------------------------------------------------------------------
# ensure_repo_checkout — clone failure
# ---------------------------------------------------------------------------

def test_ensure_checkout_clone_fails(tmp_path):
    target = tmp_path / "repo"
    commit = "abc12345" * 5

    def fake_run_git(args, *, timeout):
        if "clone" in args:
            return subprocess.CompletedProcess(args, 1, stderr="auth failed")
        return subprocess.CompletedProcess(args, 0)

    with patch.object(setup_repos, "run_git", fake_run_git):
        result = setup_repos.ensure_repo_checkout("o/r", commit, target)

    assert result is False


# ---------------------------------------------------------------------------
# ensure_repo_checkout — checkout failure
# ---------------------------------------------------------------------------

def test_ensure_checkout_checkout_fails(tmp_path):
    target = tmp_path / "repo"
    commit = "abc12345" * 5

    def fake_run_git(args, *, timeout):
        if "clone" in args:
            target.mkdir(parents=True, exist_ok=True)
            (target / ".git").mkdir()
            return subprocess.CompletedProcess(args, 0)
        if "checkout" in args:
            return subprocess.CompletedProcess(args, 1, stderr="bad commit")
        return subprocess.CompletedProcess(args, 0)

    with patch.object(setup_repos, "run_git", fake_run_git):
        with patch.object(setup_repos, "disable_lfs"):
            result = setup_repos.ensure_repo_checkout("o/r", commit, target)

    assert result is False


# ---------------------------------------------------------------------------
# ensure_repo_checkout — not a git repo
# ---------------------------------------------------------------------------

def test_ensure_checkout_not_git_repo(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    # No .git dir

    result = setup_repos.ensure_repo_checkout("o/r", "abc12345" * 5, target)
    assert result is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
