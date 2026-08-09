# tests/test_history_delta.py
from pathlib import Path

import pytest

from cybergraph.build import build_graph
from cybergraph.graph import Finding, GraphStore
from cybergraph.history import format_delta_line, list_scans, record_scan, scan_delta


def _set_findings(repo: Path, msgs: list[str]):
    store = GraphStore.open_for_repo(repo)
    try:
        store.clear_for_rebuild()
        store.add_findings([Finding(rule_id="CG-SINK", severity="high", message=m,
                                    file_path="app.py", line_start=1) for m in msgs])
    finally:
        store.close()


def test_scan_delta_between_two_scans(tmp_path: Path):
    _set_findings(tmp_path, ["a", "b"])
    record_scan(tmp_path)
    _set_findings(tmp_path, ["b", "c"])   # a removed, c added, b persists
    record_scan(tmp_path)
    d = scan_delta(tmp_path)
    assert d.is_first is False
    assert len(d.new) == 1 and len(d.fixed) == 1 and len(d.persisting) == 1


def test_delta_on_first_scan_is_all_new(tmp_path: Path):
    _set_findings(tmp_path, ["a"])
    record_scan(tmp_path)
    d = scan_delta(tmp_path)
    assert d.is_first is True and len(d.new) == 1


def test_list_scans_and_format(tmp_path: Path):
    _set_findings(tmp_path, ["a"])
    record_scan(tmp_path)
    rows = list_scans(tmp_path)
    assert len(rows) == 1 and "finding_count" in rows[0]
    line = format_delta_line(scan_delta(tmp_path))
    assert "new" in line


# --- A suppressed vulnerability must never read as a fixed one ----------------

VULNERABLE = (
    "from fastapi import FastAPI\n"
    "import subprocess\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/r")\n'
    "def run(cmd: str):\n"
    '    subprocess.run("echo " + cmd, shell=True)\n'
)


def _repo_with_a_live_vulnerability(tmp_path: Path) -> Path:
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    build_graph(tmp_path)
    first = record_scan(tmp_path)
    assert len(first.new) == 1, first  # precondition: there is something to lie about
    return tmp_path


@pytest.mark.parametrize(
    "config",
    [
        pytest.param('[suppressions]\nrules = ["CG-CMD-EXEC"]\n', id="suppressions-rules"),
        pytest.param('[suppressions]\npaths = ["legacy/**"]\n', id="suppressions-paths"),
        pytest.param('[ignore]\npaths = ["legacy/**"]\n', id="ignore-paths"),
    ],
)
def test_adding_a_suppression_is_not_a_fixed_finding(tmp_path: Path, config: str):
    """The third surface this exact lie appeared on, and the two config keys it used.

    Measured before the fix, with the vulnerable file byte-identical across both
    scans and only `.cybergraph.toml` added between them: `record_scan` returned
    ``fixed=['a101...']`` and the delta line read ``-1 fixed``. `[ignore] paths`
    is covered too -- a file the collector never opened is hidden harder still.
    """
    repo = _repo_with_a_live_vulnerability(tmp_path)
    (repo / ".cybergraph.toml").write_text(config, encoding="utf-8")
    build_graph(repo)
    second = record_scan(repo)

    assert "shell=True" in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert second.fixed == [], second.fixed
    assert len(second.hidden_by_config) == 1, second.hidden_by_config

    delta = scan_delta(repo)
    assert delta.fixed == [], delta.fixed
    assert len(delta.hidden_by_config) == 1
    line = format_delta_line(delta)
    assert "-0 fixed" in line, line
    assert "1 hidden by config (hidden, not fixed)" in line, line


def test_a_finding_hidden_by_config_stays_open_and_never_reads_as_a_regression(tmp_path: Path):
    """Dropping the suppression again must not manufacture a regression.

    Marking the row `fixed` and reopening it later would report a vulnerability
    that never went away as one that came back.
    """
    repo = _repo_with_a_live_vulnerability(tmp_path)
    (repo / ".cybergraph.toml").write_text(
        '[suppressions]\nrules = ["CG-CMD-EXEC"]\n', encoding="utf-8"
    )
    build_graph(repo)
    record_scan(repo)

    (repo / ".cybergraph.toml").unlink()
    build_graph(repo)
    third = record_scan(repo)

    assert third.regressed == [], third.regressed
    assert len(third.persisting) == 1, third.persisting


def test_a_real_fix_is_still_reported_as_fixed(tmp_path: Path):
    """The calibration half: containment must not swallow genuine repairs."""
    repo = _repo_with_a_live_vulnerability(tmp_path)
    (repo / "legacy" / "app.py").write_text(
        VULNERABLE.replace('subprocess.run("echo " + cmd, shell=True)', "return cmd"),
        encoding="utf-8",
    )
    build_graph(repo)
    second = record_scan(repo)

    assert len(second.fixed) == 1, second.fixed
    assert second.hidden_by_config == []
    assert "-1 fixed" in format_delta_line(scan_delta(repo))
