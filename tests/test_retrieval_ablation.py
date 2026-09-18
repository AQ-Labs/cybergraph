"""Guard the descriptive ablation's ranking and context-budget semantics."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from cybergraph.rag.grounded import Citation, EvidenceRecord, retrieve_records

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "retrieval_ablation", ROOT / "benchmark/run_retrieval_ablation.py"
)
ablation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ablation)


def record(title, detail="query", kind="sink"):
    return EvidenceRecord(kind, "sink_reachability", title, detail, Citation("app.py", 1))


def test_empty_pool():
    assert ablation.retrieve([], "query") == ([], 0)


def test_two_record_limit_and_stable_ties():
    selected, size = ablation.retrieve([record("C"), record("B"), record("A")], "query")
    assert [r.title for r in selected] == ["A", "B"]
    assert size == len("\n\n".join(map(ablation.render, selected)))


def test_oversized_record_is_skipped_without_truncating():
    selected, size = ablation.retrieve(
        [record("A", "query " * 400, kind="attack_path"), record("B")], "query"
    )
    assert [r.title for r in selected] == ["B"]
    assert selected[0].detail == "query"
    assert size <= 2000


def test_character_limit_includes_record_separator(monkeypatch):
    records = [record("A"), record("B")]
    size = sum(len(ablation.render(r)) for r in records)
    monkeypatch.setitem(ablation.PROTOCOL, "limit_characters", size + 1)
    selected, _ = ablation.retrieve(records, "query")
    assert len(selected) == 1
    monkeypatch.setitem(ablation.PROTOCOL, "limit_characters", size + 2)
    selected, _ = ablation.retrieve(records, "query")
    assert len(selected) == 2


def test_ranking_matches_production_on_existing_fixture(tmp_path):
    import shutil

    from cybergraph.build import build_graph
    from cybergraph.rag.grounded import collect_records

    source = ROOT / "benchmark/cases/py_django_sqli"
    target = tmp_path / "fixture"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns(".cybergraph", "__pycache__"))
    build_graph(target)
    question = "What sensitive sink is reachable from route:users/?"
    selected, size = ablation.retrieve(collect_records(target), question)
    assert selected == retrieve_records(target, question, limit=2)
    assert size <= 2000
