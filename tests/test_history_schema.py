# tests/test_history_schema.py
from pathlib import Path

from cybergraph.graph import GraphStore


def test_history_tables_exist_and_version_seeded(tmp_path: Path):
    store = GraphStore.open_for_repo(tmp_path)
    try:
        names = {r["name"] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"meta", "scans", "scan_findings", "finding_history"} <= names
        ver = store.conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert ver is not None and ver["value"] == "2"
    finally:
        store.close()


def test_history_tables_survive_clear_for_rebuild(tmp_path: Path):
    store = GraphStore.open_for_repo(tmp_path)
    try:
        store.conn.execute("INSERT INTO scans(ts) VALUES ('2026-01-01T00:00:00+00:00')")
        store.conn.commit()
        store.clear_for_rebuild()
        assert store.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    finally:
        store.close()
