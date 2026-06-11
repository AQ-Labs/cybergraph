"""Build orchestration for CyberGraph."""

from __future__ import annotations

from pathlib import Path

from cybergraph.config import load_config
from cybergraph.analysis import (
    analyze_dependency_manifest,
    analyze_javascript_file,
    analyze_python_file,
    is_dependency_manifest,
    iter_source_files,
)
from cybergraph.analysis.resolve import resolve_calls
from cybergraph.graph import Edge, Finding, GraphStore, Node
from cybergraph.suppressions import filter_suppressed_findings


def build_graph(repo_root: Path) -> dict[str, int]:
    repo_root = repo_root.resolve()
    config = load_config(repo_root)
    store = GraphStore.open_for_repo(repo_root)
    store.clear()

    nodes: list[Node] = []
    edges: list[Edge] = []
    findings: list[Finding] = []

    for path in iter_source_files(repo_root, ignored_paths=config.ignored_paths):
        if is_dependency_manifest(path):
            file_nodes, file_edges = analyze_dependency_manifest(path, repo_root)
            nodes.extend(file_nodes)
            edges.extend(file_edges)
        elif path.suffix == ".py":
            file_nodes, file_edges, file_findings = analyze_python_file(
                path,
                repo_root,
                custom_sinks=config.custom_sinks,
                auth_markers=config.auth_markers,
                validation_markers=config.validation_markers,
                secret_markers=config.secret_markers,
            )
            nodes.extend(file_nodes)
            edges.extend(file_edges)
            findings.extend(file_findings)
        elif path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
            file_nodes, file_edges, file_findings = analyze_javascript_file(
                path,
                repo_root,
                custom_sinks=config.custom_sinks,
                secret_markers=config.secret_markers,
            )
            nodes.extend(file_nodes)
            edges.extend(file_edges)
            findings.extend(file_findings)
        else:
            rel = path.relative_to(repo_root).as_posix()
            nodes.append(Node("File", rel, rel, rel, 1, len(path.read_text(errors="ignore").splitlines())))

    findings = filter_suppressed_findings(findings, config)

    # Link call sites to function definitions across files for interprocedural
    # reachability. Non-destructive: original CALLS edges are preserved.
    edges.extend(resolve_calls(nodes, edges))

    store.upsert_nodes(nodes)
    store.add_edges(edges)
    store.add_findings(findings)
    counts = store.counts()
    store.close()
    return counts


def scan_repo(repo_root: Path) -> dict[str, int]:
    return build_graph(repo_root)
