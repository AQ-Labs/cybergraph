"""Attack-path analysis over CyberGraph edges.

Traversal is interprocedural: it follows ``CALLS_RESOLVED`` edges (call sites
linked to function definitions across files) so a path can cross modules and
application layers (route handler -> service -> repository -> sink). Each path
carries a confidence derived from the weakest resolved edge it traverses, and a
``sanitized`` flag when a validation/sanitizer barrier sits on the path. A
shallow mode (``interprocedural=False``) reproduces the old intra-function
behaviour for ablation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import (
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_REACHES_SINK,
    EDGE_SANITIZES,
)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
_RANK_CONF = {3: "high", 2: "medium", 1: "low"}


@dataclass(frozen=True)
class AttackPath:
    entrypoint: str
    sink: str
    nodes: tuple[str, ...]
    confidence: str = "high"
    sanitized: bool = False


def find_attack_paths(
    repo_root: Path,
    max_depth: int = 8,
    limit: int = 20,
    interprocedural: bool = True,
) -> list[AttackPath]:
    store = GraphStore.open_for_repo(repo_root)
    try:
        entrypoints = [
            row["target"]
            for row in store.conn.execute(
                "SELECT target FROM edges WHERE kind = ? ORDER BY target",
                (EDGE_EXPOSES_ENTRYPOINT,),
            )
        ]
        sinks: dict[str, list[str]] = {}
        for row in store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_REACHES_SINK,)
        ):
            sinks.setdefault(row["source"], []).append(row["target"])

        sanitizers = {
            row["source"]
            for row in store.conn.execute(
                "SELECT source FROM edges WHERE kind = ?", (EDGE_SANITIZES,)
            )
        }

        callgraph: dict[str, list[tuple[str, str]]] = {}
        if interprocedural:
            for row in store.conn.execute(
                "SELECT source, target, properties FROM edges WHERE kind = ?",
                (EDGE_CALLS_RESOLVED,),
            ):
                confidence = _confidence_from_properties(row["properties"])
                callgraph.setdefault(row["source"], []).append((row["target"], confidence))

        return _traverse(entrypoints, sinks, sanitizers, callgraph, max_depth, limit)
    finally:
        store.close()


def _traverse(
    entrypoints: list[str],
    sinks: dict[str, list[str]],
    sanitizers: set[str],
    callgraph: dict[str, list[tuple[str, str]]],
    max_depth: int,
    limit: int,
) -> list[AttackPath]:
    paths: list[AttackPath] = []
    seen_paths: set[tuple[str, str, tuple[str, ...]]] = set()

    for entry in entrypoints:
        if len(paths) >= limit:
            break
        # queue items: (node, path, confidence_rank, sanitized)
        start_sanitized = entry in sanitizers
        queue: deque[tuple[str, tuple[str, ...], int, bool]] = deque(
            [(entry, (entry,), 3, start_sanitized)]
        )
        visited: set[str] = {entry}
        while queue and len(paths) < limit:
            node, path, conf_rank, sanitized = queue.popleft()

            for sink_name in sinks.get(node, []):
                key = (entry, sink_name, path + (sink_name,))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                paths.append(
                    AttackPath(
                        entrypoint=entry,
                        sink=sink_name,
                        nodes=path + (sink_name,),
                        confidence=_RANK_CONF[conf_rank],
                        sanitized=sanitized,
                    )
                )
                if len(paths) >= limit:
                    break

            if len(path) > max_depth:
                continue
            for nxt, edge_conf in callgraph.get(node, []):
                if nxt in visited:
                    continue
                visited.add(nxt)
                queue.append(
                    (
                        nxt,
                        path + (nxt,),
                        min(conf_rank, _CONF_RANK.get(edge_conf, 1)),
                        sanitized or nxt in sanitizers,
                    )
                )
    return paths


def format_attack_paths(paths: list[AttackPath]) -> str:
    if not paths:
        return "No entrypoint-to-sink paths found yet. Build the graph and check route decorators/sink calls."
    lines = ["Potential attack paths:"]
    for path in paths:
        flags = f"confidence={path.confidence}"
        if path.sanitized:
            flags += ", validated"
        lines.append(f"- {path.entrypoint} -> {path.sink} ({flags})")
        lines.append(f"  path: {' -> '.join(path.nodes)}")
    return "\n".join(lines)


def _confidence_from_properties(raw: str | None) -> str:
    if not raw:
        return "high"
    import json

    try:
        props = json.loads(raw)
    except (TypeError, ValueError):
        return "high"
    return props.get("confidence", "high") if isinstance(props, dict) else "high"
