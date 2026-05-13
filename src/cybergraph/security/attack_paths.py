"""Attack-path analysis over CyberGraph edges."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.ontology import EDGE_EXPOSES_ENTRYPOINT, EDGE_REACHES_SINK


@dataclass(frozen=True)
class AttackPath:
    entrypoint: str
    sink: str
    nodes: tuple[str, ...]


def find_attack_paths(repo_root: Path, max_depth: int = 5, limit: int = 20) -> list[AttackPath]:
    store = GraphStore.open_for_repo(repo_root)
    try:
        entrypoints = [
            row["target"]
            for row in store.conn.execute(
                "SELECT target FROM edges WHERE kind = ? ORDER BY target", (EDGE_EXPOSES_ENTRYPOINT,)
            )
        ]
        sinks = {
            row["source"]: row["target"]
            for row in store.conn.execute("SELECT source, target FROM edges WHERE kind = ?", (EDGE_REACHES_SINK,))
        }
        calls: dict[str, list[str]] = {}
        for row in store.conn.execute("SELECT source, target FROM edges WHERE kind = 'CALLS'"):
            calls.setdefault(row["source"], []).append(row["target"])

        paths: list[AttackPath] = []
        for entry in entrypoints:
            queue: deque[tuple[str, tuple[str, ...]]] = deque([(entry, (entry,))])
            seen = {entry}
            while queue and len(paths) < limit:
                node, path = queue.popleft()
                if node in sinks:
                    paths.append(AttackPath(entry, sinks[node], path + (sinks[node],)))
                    continue
                if len(path) > max_depth:
                    continue
                for nxt in calls.get(node, []):
                    if nxt in seen:
                        continue
                    seen.add(nxt)
                    queue.append((nxt, path + (nxt,)))
        return paths
    finally:
        store.close()


def format_attack_paths(paths: list[AttackPath]) -> str:
    if not paths:
        return "No entrypoint-to-sink paths found yet. Build the graph and check route decorators/sink calls."
    lines = ["Potential attack paths:"]
    for path in paths:
        lines.append(f"- {path.entrypoint} -> {path.sink}")
        lines.append(f"  path: {' -> '.join(path.nodes)}")
    return "\n".join(lines)
