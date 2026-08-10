from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.security.capability import CAPABILITIES, FAIL
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_both_web_capabilities_supported():
    assert _cap("client_secret_boundary").supported is True
    assert _cap("cross_origin_policy").supported is True


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_python_credentialed_cors_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "cross_origin_policy" and c.status == FAIL
               for c in verdict.checks)


def test_next_public_secret_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "config.ts").write_text(
        "export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n", encoding="utf-8"
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "client_secret_boundary" and c.status == FAIL
               for c in verdict.checks)
