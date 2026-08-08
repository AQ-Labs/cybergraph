from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.rag import answer_question
from cybergraph.security.attack_paths import find_attack_paths


def test_vulnerable_fastapi_example_builds() -> None:
    repo = Path("examples/vulnerable-fastapi")

    counts = build_graph(repo)
    answer = answer_question(repo, "routes sql")
    paths = find_attack_paths(repo)

    assert counts["nodes"] >= 5
    assert counts["edges"] >= 4
    assert "raw_sql" in answer or "CG-SQL-EXEC" in answer
    # Interprocedural: the /users route reaches the query through raw_sql.
    assert any("app.py::raw_sql" in p.nodes for p in paths)


def test_vulnerable_go_example_has_connected_path() -> None:
    repo = Path("examples/vulnerable-go")

    counts = build_graph(repo)
    paths = find_attack_paths(repo)

    assert counts["findings"] >= 1
    # Interprocedural: the /users route reaches db.Query through listUsers.
    assert any("main.go::listUsers" in p.nodes for p in paths)


def test_vulnerable_express_example_builds() -> None:
    repo = Path("examples/vulnerable-express")

    counts = build_graph(repo)

    assert counts["findings"] >= 1  # the SQL sink in listUsers
    answer = answer_question(repo, "database query")
    assert "db.query" in answer.lower() or "CG-JS-SINK-CALL" in answer
