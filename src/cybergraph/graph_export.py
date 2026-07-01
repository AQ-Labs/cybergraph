"""Export the CyberGraph database to a Cytoscape-friendly JSON document.

The interactive HTML explorer and the ``cybergraph export-json`` command both
consume this. Edge endpoints for relationships such as ``REACHES_SINK`` or
``GUARDS`` are stored as plain call-name strings rather than node rows, so we
synthesize lightweight nodes for them (a sink, guard, secret, or validator) to
keep the rendered graph meaningful.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.layers import summarize_layers

# Visual grouping used by the explorer stylesheet. Keep these keys stable: the
# Cytoscape stylesheet in the HTML report maps each one to a colour/shape.
GROUP_FILE = "file"
GROUP_ENTRYPOINT = "entrypoint"
GROUP_FUNCTION = "function"
GROUP_GUARD = "guard"
GROUP_VALIDATOR = "validator"
GROUP_SINK = "sink"
GROUP_SECRET = "secret"
GROUP_DATAFLOW = "dataflow"
GROUP_DEPENDENCY = "dependency"
GROUP_VULNERABILITY = "vulnerability"
GROUP_CALL = "call"

# Edge kind -> the group a *synthesized* (otherwise unknown) target should take.
_EDGE_TARGET_GROUP = {
    "REACHES_SINK": GROUP_SINK,
    "GUARDS": GROUP_GUARD,
    "USES_SECRET": GROUP_SECRET,
    "SANITIZES": GROUP_VALIDATOR,
    "READS_INPUT": GROUP_DATAFLOW,
    "FLOWS_TO": GROUP_DATAFLOW,
    "TAINTS": GROUP_SINK,
    "CALLS": GROUP_CALL,
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": -1}


def build_graph_data(repo_root: Path, max_nodes: int = 600) -> dict[str, Any]:
    """Build a self-contained graph document for the repository's stored graph."""
    repo_root = repo_root.resolve()
    store = GraphStore.open_for_repo(repo_root)
    try:
        node_rows = store.conn.execute(
            "SELECT kind, key, name, file_path, line_start, line_end, properties FROM nodes"
        ).fetchall()
        edge_rows = store.conn.execute(
            "SELECT kind, source, target, file_path, line FROM edges"
        ).fetchall()
        finding_rows = store.conn.execute(
            "SELECT rule_id, severity, message, file_path, line_start, line_end FROM findings"
        ).fetchall()
        counts = store.counts()
    finally:
        store.close()

    nodes: dict[str, dict[str, Any]] = {}
    for row in node_rows:
        props = _loads(row["properties"])
        nodes[row["key"]] = {
            "id": row["key"],
            "label": row["name"],
            "group": _node_group(row["kind"], props),
            "kind": row["kind"],
            "file": row["file_path"] or "",
            "line": row["line_start"] or 0,
            "properties": props,
            "severity": "",
            "findings": [],
            "synthetic": False,
        }

    edges: list[dict[str, Any]] = []
    for index, row in enumerate(edge_rows):
        source = _ensure_node(nodes, row["source"], _EDGE_TARGET_GROUP.get(row["kind"], GROUP_CALL))
        target = _ensure_node(nodes, row["target"], _EDGE_TARGET_GROUP.get(row["kind"], GROUP_CALL))
        edges.append(
            {
                "id": f"e{index}",
                "source": source,
                "target": target,
                "kind": row["kind"],
                "file": row["file_path"] or "",
                "line": row["line"] or 0,
            }
        )

    _attach_findings(nodes, finding_rows)

    attack_paths = [
        {"entrypoint": path.entrypoint, "sink": path.sink, "nodes": list(path.nodes)}
        for path in find_attack_paths(repo_root, limit=50)
    ]
    layers = [asdict(layer) for layer in summarize_layers(repo_root)]

    node_list = _cap_nodes(list(nodes.values()), edges, max_nodes)
    kept = {node["id"] for node in node_list}
    edge_list = [edge for edge in edges if edge["source"] in kept and edge["target"] in kept]

    return {
        "counts": counts,
        "nodes": node_list,
        "edges": edge_list,
        "layers": layers,
        "attack_paths": attack_paths,
        "truncated": len(node_list) < len(nodes),
    }


def export_graph_json(repo_root: Path, output: Path, max_nodes: int = 600) -> Path:
    """Write the graph document to ``output`` as pretty JSON."""
    data = build_graph_data(repo_root, max_nodes=max_nodes)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return output


def _node_group(kind: str, props: dict[str, Any]) -> str:
    if kind == "File":
        return GROUP_FILE
    if kind in {"Dependency", "DependencyManifest"}:
        return GROUP_DEPENDENCY
    if kind == "Vulnerability":
        return GROUP_VULNERABILITY
    if kind in {"Input", "DataFlow"}:
        return GROUP_DATAFLOW
    if kind == "Function":
        if props.get("entrypoint") or props.get("route"):
            return GROUP_ENTRYPOINT
        return GROUP_FUNCTION
    return GROUP_FUNCTION


def _ensure_node(nodes: dict[str, dict[str, Any]], key: str, group: str) -> str:
    existing = nodes.get(key)
    if existing is None:
        nodes[key] = {
            "id": key,
            "label": key.rsplit("::", 1)[-1],
            "group": group,
            "kind": "Synthetic",
            "file": "",
            "line": 0,
            "properties": {},
            "severity": "",
            "findings": [],
            "synthetic": True,
        }
    elif existing["synthetic"] and existing["group"] == GROUP_CALL and group != GROUP_CALL:
        # A node first seen via a generic CALLS edge can be upgraded once a more
        # specific security relationship (sink/guard/secret/validator) targets it.
        existing["group"] = group
    return key


def _attach_findings(nodes: dict[str, dict[str, Any]], finding_rows) -> None:
    by_file: dict[str, list[dict[str, Any]]] = {}
    for row in finding_rows:
        by_file.setdefault(row["file_path"], []).append(
            {
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "message": row["message"],
                "line": row["line_start"] or 0,
            }
        )
    for node in nodes.values():
        if not node["file"] or node["file"] not in by_file:
            continue
        start = node["line"] or 0
        end = node["properties"].get("line_end") if isinstance(node["properties"], dict) else None
        end = end or start
        for finding in by_file[node["file"]]:
            line = finding["line"]
            within = start <= line <= max(end, start) if node["kind"] == "Function" else line == start
            if within or (node["kind"] != "Function" and node["group"] != GROUP_FILE and line == start):
                node["findings"].append(finding)
                if _SEVERITY_RANK.get(finding["severity"], -1) > _SEVERITY_RANK.get(node["severity"], -1):
                    node["severity"] = finding["severity"]


def _cap_nodes(node_list: list[dict[str, Any]], edges, max_nodes: int) -> list[dict[str, Any]]:
    if len(node_list) <= max_nodes:
        return node_list
    # Priority: keep security-relevant nodes and anything with findings; drop
    # generic synthesized call nodes first so large repos stay responsive.
    priority = {
        GROUP_ENTRYPOINT: 0,
        GROUP_SINK: 1,
        GROUP_VULNERABILITY: 1,
        GROUP_SECRET: 2,
        GROUP_GUARD: 2,
        GROUP_VALIDATOR: 2,
        GROUP_DATAFLOW: 3,
        GROUP_DEPENDENCY: 3,
        GROUP_FUNCTION: 4,
        GROUP_FILE: 5,
        GROUP_CALL: 6,
    }
    ranked = sorted(
        node_list,
        key=lambda n: (0 if n["findings"] else 1, priority.get(n["group"], 7), n["id"]),
    )
    return ranked[:max_nodes]


def _loads(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
