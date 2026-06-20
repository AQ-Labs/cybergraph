"""Build orchestration for CyberGraph."""

from __future__ import annotations

from pathlib import Path

from cybergraph.config import load_config
from cybergraph.analysis import (
    analyze_dependency_manifest,
    is_dependency_manifest,
    iter_source_files,
)
from cybergraph.analysis.registry import analyze_source_file
from cybergraph.analysis.resolve import resolve_calls
from cybergraph.analysis.dep_usage import link_dependency_usage
from cybergraph.analysis.resource_refs import resolve_resource_references
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
            continue
        file_nodes, file_edges, file_findings = analyze_source_file(path, repo_root, config)
        nodes.extend(file_nodes)
        edges.extend(file_edges)
        findings.extend(file_findings)

    findings = filter_suppressed_findings(findings, config)

    # Link call sites to function definitions across files for interprocedural
    # reachability. Non-destructive: original CALLS edges are preserved.
    edges.extend(resolve_calls(nodes, edges))

    # Link imported modules to declared dependencies (USES_DEPENDENCY) so
    # reachability-based SCA can prioritize vulnerabilities in *used* packages.
    edges.extend(link_dependency_usage(nodes, edges))

    # Link IaC resources that reference each other (REFERENCES_RESOLVED) so
    # cross-resource cloud attack paths can be traversed.
    edges.extend(resolve_resource_references(nodes, edges))

    store.upsert_nodes(nodes)
    store.add_edges(edges)
    store.add_findings(findings)
    counts = store.counts()
    store.close()
    return counts


def scan_repo(repo_root: Path) -> dict[str, int]:
    return build_graph(repo_root)
