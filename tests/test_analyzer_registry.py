"""Tests for the analyzer contract and language dispatch registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from cybergraph.analysis.registry import (
    ANALYZED_SUFFIXES,
    RULE_FILE_UNREADABLE,
    analyze_source_file,
)
from cybergraph.build import build_graph
from cybergraph.config import load_config
from cybergraph.graph import GraphStore


def _analyze(tmp_path: Path, name: str, body: str):
    repo = tmp_path
    (repo / name).write_text(body, encoding="utf-8")
    return analyze_source_file(repo / name, repo, load_config(repo))


def test_registry_dispatches_by_suffix(tmp_path: Path) -> None:
    assert ".py" in ANALYZED_SUFFIXES
    assert ".go" in ANALYZED_SUFFIXES
    assert ".ts" in ANALYZED_SUFFIXES

    nodes, _edges, _findings = _analyze(tmp_path, "m.go", "func main() {}\n")
    languages = {n.properties.get("language") for n in nodes if n.kind == "File"}
    assert languages == {"go"}


def test_unsupported_language_falls_back_gracefully(tmp_path: Path) -> None:
    # A Ruby file is collected but has no dedicated analyzer: it must still yield a
    # valid File node and never raise.
    nodes, edges, findings = _analyze(tmp_path, "service.rb", "def foo\n  puts 'hi'\nend\n")

    assert len(nodes) == 1
    assert nodes[0].kind == "File"
    assert edges == []
    assert findings == []


# --- One unreadable file must never end the walk over the rest of the tree ----

GOOD = (
    "from fastapi import FastAPI\n"
    "import subprocess\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/r")\n'
    "def run(cmd: str):\n"
    '    subprocess.run("echo " + cmd, shell=True)\n'
)


def _rule_ids(repo: Path) -> list[str]:
    store = GraphStore.open_for_repo(repo)
    try:
        return sorted(row["rule_id"] for row in store.conn.execute("SELECT rule_id FROM findings"))
    finally:
        store.close()


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"x = 1\x00\ny = 2\n", id="nul-byte"),
        pytest.param("x = 1\n".encode("utf-16"), id="utf16"),
        pytest.param(bytes(range(256)) * 10, id="binary-blob"),
        pytest.param(b"def f(:\n    pass\n", id="syntax-error"),
        pytest.param(("x = " + "(" * 400 + "1" + ")" * 400 + "\n").encode(), id="deep-nesting"),
    ],
)
def test_one_unparsable_file_does_not_abort_the_scan(tmp_path: Path, payload: bytes) -> None:
    """Both halves are asserted: the bad file is *reported*, the good file is *analysed*.

    Measured before the fix: only the ``syntax-error`` case survived. The other
    three raised ``ValueError`` -- ``ast.parse`` refuses a NUL-bearing string,
    and ``read_text(errors="ignore")`` on a UTF-16 ``.py`` produces exactly one
    -- straight out of ``build_graph``, so a single unreadable file silenced
    every real finding in the repository. A skipped file is indistinguishable
    from a clean one, which is why the bad file is asserted present and not
    merely tolerated.
    """
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(payload)

    build_graph(tmp_path)  # must not raise

    assert _rule_ids(tmp_path) == ["CG-CMD-EXEC", "PY-SYNTAX"]


def test_a_file_that_cannot_be_opened_is_reported_not_skipped(tmp_path: Path) -> None:
    """``OSError`` is contained too: a dangling symlink, or a file deleted mid-walk.

    Exercised through the registry rather than through one analyzer, because the
    guard lives there so every language inherits it.
    """
    nodes, edges, findings = analyze_source_file(
        tmp_path / "vanished.py", tmp_path, load_config(tmp_path)
    )

    assert [node.kind for node in nodes] == ["File"]
    assert edges == []
    assert [finding.rule_id for finding in findings] == [RULE_FILE_UNREADABLE]
    assert findings[0].severity == "info"
    assert "FileNotFoundError" in findings[0].evidence


def test_a_defect_in_an_analyzer_is_not_contained(tmp_path: Path, monkeypatch) -> None:
    """The containment is a named list, not ``except Exception``.

    Swallowing every exception would render an analyzer regression across every
    file in a repository as a tidy pile of ``info`` notes -- the same silent
    miss, at scan scale.
    """
    from cybergraph.analysis import registry

    def _boom(*_args, **_kwargs):
        raise AttributeError("analyzer defect")

    monkeypatch.setattr(registry, "analyze_python_file", _boom)
    (tmp_path / "app.py").write_text(GOOD, encoding="utf-8")

    with pytest.raises(AttributeError):
        analyze_source_file(tmp_path / "app.py", tmp_path, load_config(tmp_path))
