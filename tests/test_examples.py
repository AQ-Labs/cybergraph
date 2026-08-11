from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.rag import answer_question
from cybergraph.security.attack_paths import find_attack_paths


def _rule_ids(repo: Path) -> list[str]:
    store = GraphStore.open_for_repo(repo)
    try:
        return sorted(
            row[0] for row in store.conn.execute("SELECT rule_id FROM findings").fetchall()
        )
    finally:
        store.close()


def test_vulnerable_fastapi_example_builds() -> None:
    repo = Path("examples/vulnerable-fastapi")

    counts = build_graph(repo)
    answer = answer_question(repo, "routes sql")
    paths = find_attack_paths(repo)

    assert counts["nodes"] >= 5
    assert counts["edges"] >= 4
    # Both halves asserted separately. The `or` this replaces was satisfied by
    # its left side alone, so the right side measured False and pinned nothing.
    assert "raw_sql" in answer
    # The rule the example's own `.cybergraph.toml` exists to demonstrate:
    # `sinks = ["raw_sql"]`, reached with the route's `name` in the query.
    assert _rule_ids(repo) == ["CG-CUSTOM-SINK"]
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
    # db.query is now a registered sink graded to a real verdict (CG-SQL-EXEC), not
    # the old flat CG-JS-SINK-CALL inventory finding.
    assert "CG-SQL-EXEC" in answer
    assert "query" in answer.lower()
