"""``cybergraph .`` / ``cybergraph <path>`` / ``cybergraph`` -- the no-subcommand
golden path added in Task 6 of the security decision layer. A bare path must
Just Work: detect, build if needed, check, and print the collapsed verdict."""

import subprocess
from pathlib import Path

from cybergraph.cli import main

FASTAPI_APP = '''
from fastapi import FastAPI

app = FastAPI()


@app.get("/search")
def search(term: str):
    return cursor.execute("SELECT * FROM t WHERE n = " + term)
'''

CLEAN_APP = "def add(a, b):\n    return a + b\n"


def _write_fastapi_app(repo: Path) -> Path:
    """A clean baseline committed, then overwritten with a FastAPI route that
    introduces a SQL-injection sink -- an uncommitted worktree change is what
    ``check_change`` flags as REVIEW (a committed-and-unchanged risk is not
    a *new* one)."""
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    (repo / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=repo, check=True,
    )
    (repo / "app.py").write_text(FASTAPI_APP, encoding="utf-8")
    return repo


def test_bare_path_runs_start(tmp_path, capsys):
    _write_fastapi_app(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "REVIEW" in out or "ACCEPT" in out
    assert "cybergraph" in out.lower()  # suggests a next command


def test_bare_path_review_is_advisory_by_default(tmp_path, capsys):
    """No --fail-on-review equivalent on a bare invocation: REVIEW still exits 0,
    matching the hook's advisory default."""
    _write_fastapi_app(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "REVIEW" in out
    assert rc == 0


def test_bare_path_prints_framework_summary(tmp_path, capsys):
    _write_fastapi_app(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "route" in out.lower()
    assert "sink" in out.lower()
    assert "FastAPI" in out


def test_bare_path_accepts_a_clean_repo(tmp_path, capsys):
    (tmp_path / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ACCEPT" in out


def test_no_args_uses_cwd(tmp_path, capsys, monkeypatch):
    _write_fastapi_app(tmp_path)
    monkeypatch.chdir(tmp_path)
    rc = main([])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "REVIEW" in out or "ACCEPT" in out


def test_bare_path_rejects_a_missing_directory(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    rc = main([str(missing)])
    assert rc == 1


def test_existing_subcommand_name_still_routes_there_not_to_start(tmp_path, capsys):
    """A first arg that happens to be a registered subcommand name must still
    dispatch to that subcommand, never to the bare-path start flow."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")

    rc = main(["build", str(repo)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Built security graph" in out
