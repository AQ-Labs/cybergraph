"""Build orchestration for CyberGraph."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis import analyze_python_file, iter_source_files
from cybergraph.graph import Edge, Finding, GraphStore, Node


def build_graph(repo_root: Path) -> dict[str, int]:
    repo_root = repo_root.resolve()
    store = GraphStore.open_for_repo(repo_root)
    store.clear()

    nodes: list[Node] = []
    edges: list[Edge] = []
    findings: list[Finding] = []

    for path in iter_source_files(repo_root):
        if path.suffix == ".py":
            file_nodes, file_edges, file_findings = analyze_python_file(path, repo_root)
            nodes.extend(file_nodes)
            edges.extend(file_edges)
            findings.extend(file_findings)
        else:
            rel = path.relative_to(repo_root).as_posix()
            nodes.append(Node("File", rel, rel, rel, 1, len(path.read_text(errors="ignore").splitlines())))

    store.upsert_nodes(nodes)
    store.add_edges(edges)
    store.add_findings(findings)
    counts = store.counts()
    store.close()
    return counts


def scan_repo(repo_root: Path) -> dict[str, int]:
    return build_graph(repo_root)
