"""Link imported modules to declared dependencies.

Per-file analyzers emit ``IMPORTS`` edges whose target is a bare module/package
name (for example ``fastapi`` or ``@scope/pkg``). This pass connects those imports
to the ``Dependency`` nodes parsed from manifests and emits non-destructive
``USES_DEPENDENCY`` edges (File -> Dependency.key) for the matches. It is the SCA
analog of :mod:`cybergraph.analysis.resolve`: it grounds reachability-based
dependency analysis so a vulnerability in a *used* package can be prioritized over
one merely *declared*.

Matching is name-based and conservative: a normalized exact match (lowercased,
``-``/``_`` folded) plus a small alias table for the common import-name != package-
name cases. No match means no edge — the dependency simply stays "declared-only",
so an undetected (e.g. transitive or dynamically imported) package is never falsely
asserted as unused; the SCA layer downgrades it but never drops it.
"""

from __future__ import annotations

from cybergraph.graph.models import Edge, Node
from cybergraph.security.ontology import EDGE_IMPORTS, EDGE_USES_DEPENDENCY

# import name -> distribution/package name as it appears in manifests.
IMPORT_ALIASES: dict[str, str] = {
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "pil": "pillow",
    "cv2": "opencv-python",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
}


def _normalize(name: str) -> str:
    """Fold case and treat ``-``/``_``/``.`` as equivalent for package matching."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def link_dependency_usage(nodes: list[Node], edges: list[Edge]) -> list[Edge]:
    """Return new ``USES_DEPENDENCY`` edges linking importing files to dependencies."""
    # Index Dependency nodes by normalized package name -> their keys.
    dep_keys_by_name: dict[str, list[str]] = {}
    for node in nodes:
        if node.kind == "Dependency":
            dep_keys_by_name.setdefault(_normalize(node.name), []).append(node.key)
    if not dep_keys_by_name:
        return []

    linked: set[tuple[str, str]] = set()
    resolved: list[Edge] = []
    for edge in edges:
        if edge.kind != EDGE_IMPORTS:
            continue
        candidates = _match_dependency(edge.target, dep_keys_by_name)
        for dep_key in candidates:
            pair = (edge.source, dep_key)
            if pair in linked:
                continue
            linked.add(pair)
            resolved.append(
                Edge(
                    EDGE_USES_DEPENDENCY,
                    edge.source,
                    dep_key,
                    edge.file_path,
                    edge.line,
                    {"module": edge.target},
                )
            )
    return resolved


def _match_dependency(module: str, dep_keys_by_name: dict[str, list[str]]) -> list[str]:
    norm = _normalize(module)
    if norm in dep_keys_by_name:
        return dep_keys_by_name[norm]
    alias = IMPORT_ALIASES.get(norm)
    if alias and _normalize(alias) in dep_keys_by_name:
        return dep_keys_by_name[_normalize(alias)]
    return []
