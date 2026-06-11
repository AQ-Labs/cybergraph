"""Tests for evidence-grounded retrieval and answering."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.rag import (
    answer_grounded,
    classify_question,
    collect_records,
)
from cybergraph.rag.grounded import (
    CATEGORY_DEPENDENCY,
    CATEGORY_SINK,
    CONFIDENCE_INSUFFICIENT,
)


def _vulnerable_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select * from users where name=' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_classify_question_routes_to_category() -> None:
    assert classify_question("Which routes reach SQL execution?") == CATEGORY_SINK
    assert classify_question("Is there authentication before this action?") == "auth_coverage"
    assert classify_question("Which dependencies are vulnerable?") == CATEGORY_DEPENDENCY


def test_collect_records_includes_sink_and_attack_path(tmp_path: Path) -> None:
    repo = _vulnerable_repo(tmp_path)
    kinds = {record.kind for record in collect_records(repo)}
    assert "sink" in kinds
    assert "attack_path" in kinds
    assert "entrypoint" in kinds


def test_answer_is_cited_with_confidence(tmp_path: Path) -> None:
    repo = _vulnerable_repo(tmp_path)
    answer = answer_grounded(repo, "Which routes reach SQL execution?")

    assert answer.category == CATEGORY_SINK
    assert answer.confidence in {"high", "medium"}
    assert answer.records, "expected supporting records"
    # Every answer carries citations and at least one points at the source file.
    assert answer.citations
    assert any("app.py" in citation for citation in answer.citations)
    assert "Confidence:" in answer.answer


def test_insufficient_evidence_is_explicit(tmp_path: Path) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    (repo / "readme.txt").write_text("no code here\n", encoding="utf-8")
    build_graph(repo)

    answer = answer_grounded(repo, "Which dependencies are vulnerable?")

    assert answer.confidence == CONFIDENCE_INSUFFICIENT
    assert "Insufficient evidence" in answer.answer
    assert answer.used_llm is False


def test_llm_answer_is_grounded_in_evidence(tmp_path: Path) -> None:
    repo = _vulnerable_repo(tmp_path)

    captured: dict[str, str] = {}

    class FakeClient:
        def complete(self, system: str, user: str) -> str:
            captured["system"] = system
            captured["user"] = user
            return "Route list_users reaches db.execute [1]."

    answer = answer_grounded(
        repo, "Which routes reach SQL execution?", client=FakeClient(), use_llm=True
    )

    assert answer.used_llm is True
    assert "list_users" in answer.answer
    # The model only ever sees graph-derived evidence, never raw uploaded code.
    assert "EVIDENCE" in captured["user"]
    assert "Never invent" in captured["system"]


def test_llm_not_called_when_evidence_insufficient(tmp_path: Path) -> None:
    repo = tmp_path / "empty2"
    repo.mkdir()
    (repo / "notes.md").write_text("nothing\n", encoding="utf-8")
    build_graph(repo)

    class ExplodingClient:
        def complete(self, system: str, user: str) -> str:  # pragma: no cover - must not run
            raise AssertionError("LLM must not be called without evidence")

    answer = answer_grounded(
        repo, "Which routes reach SQL execution?", client=ExplodingClient(), use_llm=True
    )
    assert answer.confidence == CONFIDENCE_INSUFFICIENT
    assert answer.used_llm is False
