from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.rag import answer_question
from cybergraph.security import find_attack_paths


def test_build_graph_finds_security_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    src = Path(__file__).parent / "fixtures" / "demo_app" / "app.py"
    (repo / "app.py").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    counts = build_graph(repo)

    assert counts["nodes"] >= 3
    assert counts["edges"] >= 2
    assert counts["findings"] >= 1


def test_answer_question_returns_file_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    src = Path(__file__).parent / "fixtures" / "demo_app" / "app.py"
    (repo / "app.py").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    build_graph(repo)

    answer = answer_question(repo, "sql query")

    assert "app.py" in answer
    assert "CG-SQL-EXEC" in answer


def test_attack_path_api_returns_list(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    src = Path(__file__).parent / "fixtures" / "demo_app" / "app.py"
    (repo / "app.py").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    build_graph(repo)

    paths = find_attack_paths(repo)

    assert isinstance(paths, list)
