"""Cross-resource cloud attack paths over Terraform resources.

Slice 1 modeled each resource and flagged misconfigurations (public exposure,
wildcard IAM, ...). This pass connects them: starting from a publicly exposed
resource (an external trust boundary) it walks ``REFERENCES_RESOLVED`` edges to
reach a privileged resource (wildcard IAM), surfacing paths like

    public security group -> EC2 instance -> admin IAM policy

References are treated as undirected adjacency: an attacker pivoting through a
compute resource connects exposure to privilege regardless of which way the HCL
reference points. Resolution is name-based and best-effort, so confidence is
graded by path length and never overclaimed. Pure graph reads -- no LLM.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.ontology import EDGE_REFERENCES_RESOLVED


@dataclass(frozen=True)
class IacAttackPath:
    entrypoint: str
    sink: str
    nodes: tuple[str, ...]
    confidence: str
    files: tuple[str, ...]


def _confidence(hops: int) -> str:
    if hops <= 2:
        return "high"
    if hops <= 4:
        return "medium"
    return "low"


def find_iac_attack_paths(repo_root: Path, max_depth: int = 6, limit: int = 20) -> list[IacAttackPath]:
    """Return paths from publicly exposed resources to privileged resources."""
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        names: dict[str, str] = {}
        files: dict[str, str] = {}
        public: list[str] = []
        privileged: set[str] = set()
        for row in store.conn.execute(
            "SELECT key, name, file_path, properties FROM nodes WHERE kind = 'Resource'"
        ):
            props = json.loads(row["properties"] or "{}")
            names[row["key"]] = row["name"]
            files[row["key"]] = row["file_path"]
            if props.get("public_exposure"):
                public.append(row["key"])
            if props.get("privileged"):
                privileged.add(row["key"])

        adjacency: dict[str, set[str]] = {}
        for row in store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_REFERENCES_RESOLVED,)
        ):
            adjacency.setdefault(row["source"], set()).add(row["target"])
            adjacency.setdefault(row["target"], set()).add(row["source"])  # undirected pivot
    finally:
        store.close()

    if not public or not privileged:
        return []

    paths: list[IacAttackPath] = []
    seen: set[tuple[str, str]] = set()
    for source in sorted(public):
        for path_keys in _shortest_paths_to_targets(source, privileged, adjacency, max_depth):
            sink = path_keys[-1]
            if (source, sink) in seen:
                continue
            seen.add((source, sink))
            node_names = tuple(names.get(k, k) for k in path_keys)
            path_files = tuple(dict.fromkeys(files.get(k, "") for k in path_keys if files.get(k)))
            paths.append(
                IacAttackPath(
                    entrypoint=names.get(source, source),
                    sink=names.get(sink, sink),
                    nodes=node_names,
                    confidence=_confidence(len(path_keys) - 1),
                    files=path_files,
                )
            )
            if len(paths) >= limit:
                return paths
    return paths


def _shortest_paths_to_targets(
    source: str, targets: set[str], adjacency: dict[str, set[str]], max_depth: int
) -> list[tuple[str, ...]]:
    """BFS the shortest path from ``source`` to each reachable target."""
    found: list[tuple[str, ...]] = []
    remaining = set(targets) - {source}
    queue: deque[tuple[str, ...]] = deque([(source,)])
    visited: set[str] = {source}
    while queue and remaining:
        path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for nxt in sorted(adjacency.get(path[-1], ())):
            if nxt in visited:
                continue
            visited.add(nxt)
            new_path = path + (nxt,)
            if nxt in remaining:
                found.append(new_path)
                remaining.discard(nxt)
            queue.append(new_path)
    return found


def format_iac_attack_paths(paths: list[IacAttackPath]) -> str:
    if not paths:
        return (
            "No cloud attack paths found. This needs a publicly exposed resource that "
            "references (directly or transitively) a privileged one. Build the graph first."
        )
    lines = ["Cloud attack paths (public exposure -> privileged resource):"]
    for path in paths:
        lines.append(f"- {path.entrypoint} -> {path.sink} (confidence={path.confidence})")
        lines.append(f"  path: {' -> '.join(path.nodes)}")
        if path.files:
            lines.append(f"  in: {', '.join(path.files)}")
    return "\n".join(lines)
