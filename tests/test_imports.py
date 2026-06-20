"""Tests for import capture and code->dependency usage linking."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.dep_usage import link_dependency_usage
from cybergraph.analysis.javascript import _package_specifier
from cybergraph.build import build_graph
from cybergraph.graph import Edge, GraphStore, Node


def _edges(repo: Path, kind: str) -> list[tuple[str, str]]:
    store = GraphStore.open_for_repo(repo.resolve())
    try:
        return [
            (r["source"], r["target"])
            for r in store.conn.execute(
                "SELECT source, target FROM edges WHERE kind = ?", (kind,)
            )
        ]
    finally:
        store.close()


# --- Python import capture + linking ----------------------------------------
def test_python_imports_captured_and_linked(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.110.0\nunused-lib==1.0\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "import fastapi\n"
        "from os import path\n"
        "from . import helpers\n"
        "def h():\n"
        "    return fastapi.FastAPI()\n",
        encoding="utf-8",
    )
    build_graph(repo)

    imported = {t for _, t in _edges(repo, "IMPORTS")}
    assert "fastapi" in imported
    assert "os" in imported
    assert "helpers" not in imported  # relative import is local, skipped

    used = {t for _, t in _edges(repo, "USES_DEPENDENCY")}
    assert "requirements.txt::fastapi" in used          # declared AND imported -> linked
    assert not any("unused-lib" in t for t in used)     # declared but never imported -> not linked


# --- JS specifier normalization ---------------------------------------------
def test_js_package_specifier_normalization():
    assert _package_specifier("express") == "express"
    assert _package_specifier("lodash/fp") == "lodash"       # submodule -> package
    assert _package_specifier("@scope/pkg/sub") == "@scope/pkg"  # scoped
    assert _package_specifier("./local") == ""               # relative -> local
    assert _package_specifier("../x") == ""


def test_js_imports_captured_and_linked(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"dependencies": {"express": "^4", "lodash": "^4"}}', encoding="utf-8"
    )
    (repo / "server.js").write_text(
        "import express from 'express';\n"
        "const fp = require('lodash/fp');\n"
        "import local from './local';\n",
        encoding="utf-8",
    )
    build_graph(repo)

    imported = {t for _, t in _edges(repo, "IMPORTS")}
    assert "express" in imported
    assert "lodash" in imported
    assert "./local" not in imported

    used = {t for _, t in _edges(repo, "USES_DEPENDENCY")}
    assert any("express" in t for t in used)
    assert any("lodash" in t for t in used)


# --- pure linking logic -----------------------------------------------------
def test_link_dependency_usage_alias_and_dedup():
    nodes = [Node("Dependency", "requirements.txt::PyYAML", "PyYAML", "requirements.txt")]
    edges = [
        Edge("IMPORTS", "app.py", "yaml", "app.py", 1),
        Edge("IMPORTS", "app.py", "yaml", "app.py", 2),  # same file+dep -> deduped
    ]
    linked = link_dependency_usage(nodes, edges)
    assert len(linked) == 1
    assert linked[0].kind == "USES_DEPENDENCY"
    assert linked[0].target == "requirements.txt::PyYAML"  # alias yaml -> PyYAML


def test_link_dependency_usage_no_match_no_edge():
    nodes = [Node("Dependency", "requirements.txt::fastapi", "fastapi", "requirements.txt")]
    edges = [Edge("IMPORTS", "app.py", "requests", "app.py", 1)]
    assert link_dependency_usage(nodes, edges) == []
