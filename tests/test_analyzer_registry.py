"""Tests for the analyzer contract and language dispatch registry."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.registry import ANALYZED_SUFFIXES, analyze_source_file
from cybergraph.config import load_config


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
