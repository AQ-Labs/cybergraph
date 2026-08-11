from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.coverage import assess_coverage

GOOD = "def add(a, b):\n    return a + b\n"
BROKEN = "def add(a, b)\n    return a + b\n"  # missing colon


def _status(tmp_path: Path, changed: tuple[str, ...]) -> dict[str, str]:
    build_graph(tmp_path)
    return {item.path: item.status for item in assess_coverage(tmp_path, changed)}


def test_parsed_file_is_analyzed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    assert _status(tmp_path, ("good.py",)) == {"good.py": "analyzed"}


def test_unparseable_file_is_failed_not_clean(tmp_path: Path):
    """Zero findings from a file that never parsed is not evidence of safety."""
    (tmp_path / "broken.py").write_text(BROKEN, encoding="utf-8")
    assert _status(tmp_path, ("broken.py",)) == {"broken.py": "failed"}


def test_language_without_an_analyzer_is_unsupported(tmp_path: Path):
    (tmp_path / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    assert _status(tmp_path, ("Main.java",)) == {"Main.java": "unsupported"}


def test_go_is_analyzed_now_it_has_a_partial_analyzer(tmp_path: Path):
    """Go joined the verified gate alongside Python/config/web (sql/command/path
    sinks); it is no longer reported as a blind spot at the file-coverage level.
    The stricter honesty guarantee -- Go is not a Phase-1 *verified* language --
    still holds at the capability level, where `source_analysis_support` stays
    NOT_SUPPORTED for Go (see test_go_verdicts_e2e.py)."""
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    assert _status(tmp_path, ("main.go",)) == {"main.go": "analyzed"}


def test_deleted_file_is_missing_not_failed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / "good.py").unlink()
    statuses = {i.path: i.status for i in assess_coverage(tmp_path, ("good.py", "gone.py"))}
    assert statuses["gone.py"] == "missing"


def test_non_source_file_is_not_reported(tmp_path: Path):
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    assert _status(tmp_path, ("README.md",)) == {}
