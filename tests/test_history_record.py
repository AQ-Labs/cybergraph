# tests/test_history_record.py
from pathlib import Path

from cybergraph.graph import GraphStore, Finding
from cybergraph.history import fingerprint, record_scan


def test_fingerprint_is_line_independent_and_tool_sensitive():
    a = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    b = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    assert a == b and len(a) == 40  # sha1 hex, stable regardless of line
    # different tool -> different identity (distinct evidence sources)
    assert fingerprint("CG-SINK", "semgrep", "app.py", "reaches sink `db.execute`") != a
    # different file -> different identity
    assert fingerprint("CG-SINK", "cybergraph", "other.py", "reaches sink `db.execute`") != a


def _add_finding(repo: Path, *, rule="CG-SINK", msg="reaches sink `x`", line=3):
    store = GraphStore.open_for_repo(repo)
    try:
        store.add_findings([Finding(rule_id=rule, severity="high", message=msg,
                                    file_path="app.py", line_start=line)])
    finally:
        store.close()


def _clear_findings(repo: Path):
    store = GraphStore.open_for_repo(repo)
    try:
        store.clear_for_rebuild()  # deletes tool='cybergraph' findings; keeps history tables
    finally:
        store.close()


def test_first_scan_marks_all_new(tmp_path: Path):
    _add_finding(tmp_path)
    r = record_scan(tmp_path)
    assert r.is_first is True and len(r.new) == 1 and r.fixed == [] and r.regressed == []


def test_removed_finding_becomes_fixed(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    _clear_findings(tmp_path)
    r = record_scan(tmp_path)
    assert len(r.fixed) == 1 and r.new == [] and r.is_first is False


def test_reappearing_finding_is_regressed(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    _clear_findings(tmp_path)
    record_scan(tmp_path)          # now fixed
    _add_finding(tmp_path)
    r = record_scan(tmp_path)      # back again
    assert len(r.regressed) == 1 and r.new == []
    store = GraphStore.open_for_repo(tmp_path)
    try:
        row = store.conn.execute(
            "SELECT status, reopened_count, fixed_ts FROM finding_history").fetchone()
        assert row["status"] == "open" and row["reopened_count"] == 1 and row["fixed_ts"] == ""
    finally:
        store.close()


def test_unchanged_rerun_is_no_change_without_new_scan_row(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    r = record_scan(tmp_path)      # identical set, same (empty) sha
    assert r.no_change is True and r.new == [] and r.fixed == []
    store = GraphStore.open_for_repo(tmp_path)
    try:
        assert store.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    finally:
        store.close()


def test_non_git_repo_records_without_crashing(tmp_path: Path):
    _add_finding(tmp_path)
    r = record_scan(tmp_path)      # tmp_path is not a git repo
    assert r.is_first is True
