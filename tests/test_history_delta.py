# tests/test_history_delta.py
from pathlib import Path

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
