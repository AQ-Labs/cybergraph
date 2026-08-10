from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    UNKNOWN,
)
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid: str):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_cloud_configuration_is_supported():
    assert _cap("cloud_configuration").supported is True


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@e.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_disabling_rls_makes_check_review(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    d = repo / "supabase" / "migrations"
    d.mkdir(parents=True)
    (d / "0002_open.sql").write_text(
        "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any("cloud_configuration" == c.capability_id and c.status == FAIL
               for c in verdict.checks)


def test_clean_readme_change_accepts(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "README.md").write_text("# x\nmore\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    # cloud_configuration is NOT_APPLICABLE (no config file changed); overall may
    # still accept if nothing else reviews.
    cc = next(c for c in verdict.checks if c.capability_id == "cloud_configuration")
    assert cc.status == NOT_APPLICABLE


def test_malformed_bucket_policy_reads_unknown(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "bucket-policy.json").write_text("{not json", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    cc = next(c for c in verdict.checks if c.capability_id == "cloud_configuration")
    assert cc.status == UNKNOWN  # never a silent PASS on something we could not parse
