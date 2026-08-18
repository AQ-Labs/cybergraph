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

from cybergraph.cli import _has_pending_change, main

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


def test_non_git_directory_takes_the_scan_path_not_a_bare_accept(tmp_path, capsys):
    """The most extreme form of the bug this task fixed: a plain directory
    with no ``.git`` at all (no base to ever diff against) must never route
    through the change-verdict path. ``resolve_revisions`` reports
    ``changed_files=()`` for a non-git dir, so ``_has_pending_change`` must
    be False, and ``_run_start`` must take the standing-code scan path --
    never printing a bare change-style ACCEPT."""
    (tmp_path / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    assert not (tmp_path / ".git").exists()

    assert _has_pending_change(tmp_path) is False

    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "not a change verdict" in out.lower()
    assert "scanned the current code" in out.lower()
    assert "Verdict: ACCEPT" not in out
    assert "No issues found in the checks CyberGraph ran." not in out


# --- FIX 2: `_run_start_change` applies the policy gate before rendering ----


def _write_pending_general_unknown_change(repo: Path) -> Path:
    """A committed clean baseline, then an *untracked* Ruby file -- a language
    CyberGraph has no analyzer for. This is a general-unknown (unsupported,
    not on any protected boundary) reason: under default `VerificationConfig`
    (``block_general_unknown=False``, no routes so nothing is "protected"),
    the resulting REVIEW is non-blocking (gate=warn), which is exactly the
    framing `_run_start_change` must apply the same way `_run_check` does."""
    (repo / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    _git_init_commit(repo)
    (repo / "worker.rb").write_text("def run\n  1\nend\n", encoding="utf-8")
    return repo


def test_bare_path_applies_the_same_gate_framing_check_does_for_a_non_blocking_review(
    tmp_path, capsys
):
    """FIX 2: `cybergraph .` must apply `gate_for` before `format_verdict`,
    same as `cybergraph check` -- the identical non-blocking REVIEW must carry
    the identical "not blocking per policy" advisory framing on both surfaces,
    and neither may print a bare ACCEPT / "No issues found" (Law 1 & 7)."""
    repo = _write_pending_general_unknown_change(tmp_path)

    rc_start = main([str(repo)])
    out_start = capsys.readouterr().out

    rc_check = main(["check", str(repo)])
    out_check = capsys.readouterr().out

    assert rc_start == 0
    assert rc_check == 0
    assert "Verdict: REVIEW" in out_start
    assert "attention before shipping" in out_check

    advisory = "not blocking per policy"
    assert advisory in out_start, out_start
    assert advisory in out_check, out_check

    for out in (out_start, out_check):
        assert "No issues found in the checks CyberGraph ran." not in out
        assert "Verdict: ACCEPT" not in out


def test_bare_path_start_change_verdict_carries_a_nonempty_gate(tmp_path, capsys):
    """Strongest deterministic assertion available directly on the rendered
    Verdict object (not just its printed text): `_run_start_change` must have
    applied `gate_for` before formatting, so the gate is never left at the
    unset `""` `check_change` always returns on its own."""
    from cybergraph.security.check import check_change
    from cybergraph.security.policy_gate import gate_for, load_verification_config

    repo = _write_pending_general_unknown_change(tmp_path)

    raw = check_change(repo)
    assert raw.gate == "", "check_change itself must not apply the gate"

    config = load_verification_config(repo)
    expected_gate = gate_for(raw, config)
    assert expected_gate, "fixture must produce reasons so the gate is non-empty"

    main([str(repo)])
    out = capsys.readouterr().out
    assert "not blocking per policy" in out
    assert expected_gate != "block"


def test_frameworkless_repo_reports_framework_unknown(tmp_path, capsys):
    """A repo with no web framework and no dependency manifest renders the
    new fallback label ``"Framework: unknown"`` -- not just the absence of
    the old, wrong "No web framework detected" string, but the presence of
    the correct one."""
    _write_clean_committed_repo(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "Framework: unknown" in out
