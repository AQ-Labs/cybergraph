"""Resolve Terraform resource references across the repository.

The Terraform analyzer emits ``REFERENCES`` edges whose target is a bare
``<type>.<name>`` string (parsed from interpolations like
``aws_security_group.web.id``). This pass links those to the actual ``Resource``
nodes and emits non-destructive ``REFERENCES_RESOLVED`` edges, mirroring how
``resolve.py`` links calls and ``dep_usage.py`` links imports. It is the graph
foundation for cross-resource cloud attack paths (public exposure -> compute ->
privileged IAM). Unresolved references (e.g. data sources or resources outside the
scanned files) are simply dropped.
"""

from __future__ import annotations

from cybergraph.graph.models import Edge, Node
from cybergraph.security.ontology import EDGE_REFERENCES, EDGE_REFERENCES_RESOLVED


def resolve_resource_references(nodes: list[Node], edges: list[Edge]) -> list[Edge]:
    """Return new ``REFERENCES_RESOLVED`` edges linking resources to resources."""
    key_by_name: dict[str, str] = {}
    for node in nodes:
        if node.kind == "Resource":
            key_by_name.setdefault(node.name, node.key)  # node.name is "<type>.<name>"
    if not key_by_name:
        return []

    resolved: list[Edge] = []
    seen: set[tuple[str, str]] = set()
    for edge in edges:
        if edge.kind != EDGE_REFERENCES:
            continue
        target_key = key_by_name.get(edge.target)
        if not target_key or target_key == edge.source:
            continue
        pair = (edge.source, target_key)
        if pair in seen:
            continue
        seen.add(pair)
        resolved.append(
            Edge(EDGE_REFERENCES_RESOLVED, edge.source, target_key, edge.file_path, edge.line)
        )
    return resolved
