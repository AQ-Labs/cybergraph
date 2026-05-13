from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.rag import answer_question


def test_vulnerable_fastapi_example_builds() -> None:
    repo = Path("examples/vulnerable-fastapi")

    counts = build_graph(repo)
    answer = answer_question(repo, "routes sql")

    assert counts["nodes"] >= 5
    assert counts["edges"] >= 4
    assert "raw_sql" in answer or "CG-SINK-CALL" in answer
