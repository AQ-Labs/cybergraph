"""Export the CyberGraph graph as BloodHound OpenGraph JSON.

BloodHound CE's OpenGraph is a generic attack-path ingestion format, so emitting
it lets CyberGraph's code- and infrastructure-level attack paths (entrypoint ->
sink, public resource -> privileged IAM) be explored alongside identity/infra
paths in BloodHound. The competitive map calls this interop out explicitly.

We reuse :func:`cybergraph.graph_export.build_graph_data`, which already resolves
every edge endpoint to a node (synthesizing sink/guard/secret/validator nodes for
string-targeted edges), and map it to the OpenGraph schema:

    {"metadata": {"source_kind": "CyberGraph"},
     "graph": {"nodes": [{"id", "kinds": [...], "properties": {...}}],
               "edges": [{"kind", "start": {"value","match_by"}, "end": {...}, "properties": {...}}]}}

Per the schema: node ``id`` is top-level, ``kinds`` is a non-empty list (the first
entry drives the BloodHound icon), property names are lowercase, and edge ``kind``
must match ``^[A-Za-z0-9_]+$`` (CyberGraph's edge kinds already do).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cybergraph.graph_export import build_graph_data

SOURCE_KIND = "CyberGraph"
_KIND_RE = re.compile(r"[^A-Za-z0-9_]")

# Synthetic nodes (string-targeted edges) carry only a visual group; map it to a
# readable OpenGraph kind. Real nodes use their CyberGraph node kind directly.
_GROUP_KIND = {
    "sink": "Sink",
    "guard": "Guard",
    "validator": "Validator",
    "secret": "Secret",
    "call": "Call",
    "function": "Function",
    "entrypoint": "Entrypoint",
    "file": "File",
    "dependency": "Dependency",
    "vulnerability": "Vulnerability",
}


def _primary_kind(node: dict[str, Any]) -> str:
    kind = node.get("kind", "")
    # A route handler is stored as a Function with an entrypoint group; surface it
    # as an Entrypoint so BloodHound treats it as an external trust boundary.
    if kind == "Function" and node.get("group") == "entrypoint":
        return "Entrypoint"
    if kind and kind != "Synthetic":
        return kind
    return _GROUP_KIND.get(node.get("group", ""), "Node")


def _clean_properties(node: dict[str, Any]) -> dict[str, Any]:
    """Lowercase property names and keep only JSON-friendly values (schema rule)."""
    props: dict[str, Any] = {
        "name": node.get("label", node.get("id", "")),
        "displayname": node.get("label", node.get("id", "")),
        "kind": node.get("kind", ""),
        "group": node.get("group", ""),
    }
    if node.get("file"):
        props["file"] = node["file"]
    if node.get("line"):
        props["line"] = node["line"]
    if node.get("severity"):
        props["severity"] = node["severity"]
    if node.get("findings"):
        props["finding_count"] = len(node["findings"])
    for key, value in (node.get("properties") or {}).items():
        prop_key = str(key).lower()
        if isinstance(value, (str, int, float, bool)):
            props[prop_key] = value
        elif isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
            props[prop_key] = value
        else:
            props[prop_key] = json.dumps(value, sort_keys=True)
    return props


def build_opengraph(repo_root: Path, max_nodes: int = 5000) -> dict[str, Any]:
    """Build a BloodHound OpenGraph document for the repository's stored graph."""
    data = build_graph_data(Path(repo_root).resolve(), max_nodes=max_nodes)

    nodes = [
        {
            "id": node["id"],
            "kinds": [_primary_kind(node), SOURCE_KIND],
            "properties": _clean_properties(node),
        }
        for node in data["nodes"]
    ]
    edges = [
        {
            "kind": _KIND_RE.sub("_", edge["kind"]),
            "start": {"value": edge["source"], "match_by": "id"},
            "end": {"value": edge["target"], "match_by": "id"},
            "properties": {
                k: v for k, v in (("file", edge.get("file")), ("line", edge.get("line"))) if v
            },
        }
        for edge in data["edges"]
    ]
    return {
        "metadata": {"source_kind": SOURCE_KIND},
        "graph": {"nodes": nodes, "edges": edges},
    }


def export_opengraph(repo_root: Path, output: Path, max_nodes: int = 5000) -> Path:
    """Write the OpenGraph document to ``output`` as pretty JSON."""
    document = build_opengraph(repo_root, max_nodes=max_nodes)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return output
