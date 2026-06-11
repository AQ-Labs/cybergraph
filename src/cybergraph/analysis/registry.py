"""Analyzer contract and language dispatch registry.

Every language analyzer honours the same contract so its output maps onto the
shared security ontology regardless of language:

    analyze(path, repo_root, config) -> (nodes, edges, findings)

where analyzers are expected to emit, where applicable:

* a ``File`` node for the file, with a ``language`` property;
* ``Function`` nodes for definitions (keyed ``<relpath>::<name>``);
* ``Entrypoint`` nodes / ``EXPOSES_ENTRYPOINT`` edges for routes, handlers,
  webhooks, and other external inputs;
* ``GUARDS`` edges for authentication/authorization controls;
* ``SANITIZES`` edges for validation/sanitization barriers;
* ``REACHES_SINK`` edges (and a finding) for sensitive sinks;
* ``USES_SECRET`` edges for secret access;
* ``CALLS`` edges for call sites (resolved cross-file later).

Files with no specialized analyzer fall back gracefully to a bare ``File`` node
so the rest of the pipeline keeps working.
"""

from __future__ import annotations

from pathlib import Path

from cybergraph.config import CyberGraphConfig
from cybergraph.graph import Edge, Finding, Node

from .csharp import analyze_csharp_file
from .go import analyze_go_file
from .java import analyze_java_file
from .javascript import analyze_javascript_file
from .python import analyze_python_file

AnalyzerResult = tuple[list[Node], list[Edge], list[Finding]]

PYTHON_SUFFIXES = {".py"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
GO_SUFFIXES = {".go"}
JAVA_SUFFIXES = {".java"}
CSHARP_SUFFIXES = {".cs"}

# Suffixes that have a dedicated security analyzer (everything else falls back).
ANALYZED_SUFFIXES = (
    PYTHON_SUFFIXES | JAVASCRIPT_SUFFIXES | GO_SUFFIXES | JAVA_SUFFIXES | CSHARP_SUFFIXES
)


def analyze_source_file(path: Path, repo_root: Path, config: CyberGraphConfig) -> AnalyzerResult:
    """Dispatch a source file to its language analyzer, or fall back to a File node."""
    suffix = path.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return analyze_python_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            auth_markers=config.auth_markers,
            validation_markers=config.validation_markers,
            secret_markers=config.secret_markers,
        )
    if suffix in JAVASCRIPT_SUFFIXES:
        return analyze_javascript_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in GO_SUFFIXES:
        return analyze_go_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in JAVA_SUFFIXES:
        return analyze_java_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in CSHARP_SUFFIXES:
        return analyze_csharp_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    return _fallback_file_node(path, repo_root)


def _fallback_file_node(path: Path, repo_root: Path) -> AnalyzerResult:
    rel = path.relative_to(repo_root).as_posix()
    line_count = len(path.read_text(errors="ignore").splitlines())
    return [Node("File", rel, rel, rel, 1, line_count)], [], []
