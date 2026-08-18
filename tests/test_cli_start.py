"""``cybergraph .`` / ``cybergraph <path>`` / ``cybergraph`` -- the no-subcommand
golden path added in Task 6 of the security decision layer.

Two paths, dispatched on whether there is a pending change to check:
  - a pending change (staged/unstaged/untracked vs HEAD) -> the collapsed
    change-verdict (ACCEPT/REVIEW), same as `check`.
  - a clean tree (or no git base to diff against) -> a standing-code risk
    scan, never a bare change-style ACCEPT -- that would falsely claim the
    existing, un-diffed code was verified clean (the false-reassurance bug
    this file's "clean tree" tests guard against).
"""

import subprocess
from pathlib import Path

from cybergraph.cli import main

FASTAPI_SINK_APP = '''
from fastapi import FastAPI

app = FastAPI()


@app.get("/search")
def search(term: str):
    return cursor.execute("SELECT * FROM t WHERE n = " + term)
'''

CLEAN_APP = "def add(a, b):\n    return a + b\n"


def _git_init_commit(repo: Path, message: str = "base") -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", message],
        cwd=repo, check=True,
    )


def _write_pending_fastapi_vuln(repo: Path) -> Path:
    """A clean baseline committed, then overwritten with a FastAPI route that
    introduces a SQL-injection sink -- an *uncommitted* change, so
    ``check_change`` has a real diff to flag as REVIEW."""
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    (repo / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    _git_init_commit(repo)
    (repo / "app.py").write_text(FASTAPI_SINK_APP, encoding="utf-8")
    return repo


def _write_committed_fastapi_vuln(repo: Path) -> Path:
    """The SQL-injection sink is already committed and the tree is clean --
    there is nothing pending to diff, so this must NOT read as a
    verified-safe ACCEPT. Deliberately no requirements.txt: the framework
    must come from the source-text fallback, not a dependency manifest."""
    (repo / "app.py").write_text(FASTAPI_SINK_APP, encoding="utf-8")
    _git_init_commit(repo)
    return repo


def _write_clean_committed_repo(repo: Path) -> Path:
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    _git_init_commit(repo)
    return repo


# --- Pending change: the collapsed change-verdict path ----------------------


def test_bare_path_runs_start(tmp_path, capsys):
    _write_pending_fastapi_vuln(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "REVIEW" in out or "ACCEPT" in out
    assert "cybergraph" in out.lower()  # suggests a next command


def test_pending_change_with_tainted_sink_shows_review(tmp_path, capsys):
    """Regression test 2: a pending working-tree change that introduces a
    tainted sink runs the change-check and shows REVIEW."""
    _write_pending_fastapi_vuln(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "Verdict: REVIEW" in out
    assert rc == 0, "a bare-path REVIEW must not block by default"


def test_bare_path_prints_framework_summary(tmp_path, capsys):
    _write_pending_fastapi_vuln(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "route" in out.lower()
    assert "sink" in out.lower()
    assert "Framework: FastAPI" in out


def test_no_args_uses_cwd(tmp_path, capsys, monkeypatch):
    _write_pending_fastapi_vuln(tmp_path)
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
    """Regression test 3: a first arg that happens to be a registered
    subcommand name must still dispatch to that subcommand, never to the
    bare-path start flow."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")

    rc = main(["build", str(repo)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Built security graph" in out


# --- Clean tree: the standing-code scan path (the false-ACCEPT bug guard) ---


def test_clean_tree_with_committed_vuln_surfaces_it_not_a_bare_accept(tmp_path, capsys):
    """Regression test 1 (the bug guard): a clean working tree whose
    *committed* code contains a live SQL-injection sink must surface that
    risk, and must NEVER print a bare change-style ACCEPT/"No issues found"
    -- that would falsely claim the existing code was diff-checked clean."""
    _write_committed_fastapi_vuln(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No issues found in the checks CyberGraph ran." not in out
    assert "Verdict: ACCEPT" not in out
    assert "execute" in out.lower()  # the tainted sink call itself is named


def test_clean_tree_scan_explains_it_is_not_a_change_verdict(tmp_path, capsys):
    _write_committed_fastapi_vuln(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "not a change verdict" in out.lower()
    assert "scanned the current code" in out.lower()


def test_clean_tree_framework_summary_reflects_real_framework(tmp_path, capsys):
    """Regression test 4: even with no dependency manifest to read, a FastAPI
    app is identified as FastAPI, not a false "no framework detected"."""
    _write_committed_fastapi_vuln(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "Framework: FastAPI" in out
    assert "No web framework detected" not in out


def test_clean_tree_with_no_findings_is_still_a_scan_not_an_accept(tmp_path, capsys):
    """Even a genuinely clean, fully-committed repo must not print a bare
    change-style ACCEPT: there is still no diff it was checked against."""
    _write_clean_committed_repo(tmp_path)
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Verdict: ACCEPT" not in out
    assert "No issues found in the checks CyberGraph ran." not in out
    assert "scanned the current code" in out.lower()
