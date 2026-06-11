"""Cross-file call resolution.

Per-file analyzers emit ``CALLS`` edges whose target is a bare call-name string
(for example ``service.run`` or ``execute``). This pass links those calls to the
actual function definitions across the whole repository and emits non-destructive
``CALLS_RESOLVED`` edges (the original ``CALLS`` edges are left untouched). Each
resolved edge records a confidence and how it was resolved, so interprocedural
attack-path traversal can reason about reachability across modules and layers
without claiming certainty it does not have.

Resolution is name-based, not a full dataflow/type analysis: a unique
function-name match is high confidence, a same-file disambiguation is medium,
and an ambiguous match across files is low confidence (and flagged).
"""

from __future__ import annotations

from cybergraph.graph.models import Edge, Node

EDGE_CALLS_RESOLVED = "CALLS_RESOLVED"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def resolve_calls(nodes: list[Node], edges: list[Edge]) -> list[Edge]:
    """Return new ``CALLS_RESOLVED`` edges linking call sites to definitions."""
    # Function definitions are resolution *targets*; calls may originate from a
    # function or from a route Entrypoint (e.g. a Django URLconf entry that names
    # its view), so both kinds are valid call sources.
    target_keys_by_name: dict[str, list[str]] = {}
    source_keys: set[str] = set()
    for node in nodes:
        if node.kind == "Function":
            target_keys_by_name.setdefault(node.name, []).append(node.key)
            source_keys.add(node.key)
        elif node.kind == "Entrypoint":
            source_keys.add(node.key)

    keys_by_name = target_keys_by_name
    resolved: list[Edge] = []
    for edge in edges:
        if edge.kind != "CALLS" or edge.source not in source_keys:
            continue
        callee = _simple_name(edge.target)
        if not callee:
            continue
        # A call may already point at a function key (rare); skip self-loops.
        candidates = [key for key in keys_by_name.get(callee, []) if key != edge.source]
        if not candidates:
            continue
        resolved.extend(_resolve_candidates(edge, candidates))
    return resolved


def _resolve_candidates(edge: Edge, candidates: list[str]) -> list[Edge]:
    if len(candidates) == 1:
        return [_resolved_edge(edge, candidates[0], CONFIDENCE_HIGH, "unique-name", 1)]

    source_file = edge.source.split("::", 1)[0]
    same_file = [key for key in candidates if key.split("::", 1)[0] == source_file]
    if len(same_file) == 1:
        return [_resolved_edge(edge, same_file[0], CONFIDENCE_MEDIUM, "same-file", len(candidates))]

    # Ambiguous across files: link to each candidate at low confidence and flag it
    # so traversal and reviewers know the resolution is uncertain.
    return [
        _resolved_edge(edge, key, CONFIDENCE_LOW, "ambiguous", len(candidates))
        for key in candidates
    ]


def _resolved_edge(edge: Edge, target: str, confidence: str, via: str, candidates: int) -> Edge:
    return Edge(
        EDGE_CALLS_RESOLVED,
        edge.source,
        target,
        edge.file_path,
        edge.line,
        {"confidence": confidence, "via": via, "candidates": candidates, "ambiguous": via == "ambiguous"},
    )


def _simple_name(call_name: str) -> str:
    """``db.execute`` -> ``execute``; ``self.process`` -> ``process``; ``run`` -> ``run``."""
    if not call_name:
        return ""
    return call_name.rsplit(".", 1)[-1].strip()
