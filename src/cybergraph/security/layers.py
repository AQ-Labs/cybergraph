"""Security layer summaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.ontology import LAYERS


@dataclass(frozen=True)
class LayerSummary:
    key: str
    label: str
    description: str
    node_count: int
    edge_count: int
    finding_count: int


PROPERTY_TO_LAYER = {
    "auth_related": "authentication",
    "authorization_related": "authorization",
    "validation_related": "validation",
    "secret_related": "secrets",
    "crypto_related": "crypto",
    "sink_related": "sink",
}

EDGE_TO_LAYER = {
    "EXPOSES_ENTRYPOINT": "entrypoint",
    "GUARDS": "authentication",
    "SANITIZES": "validation",
    "REACHES_SINK": "sink",
    "USES_SECRET": "secrets",
    "AFFECTS_DEPENDENCY": "dependency",
}


def summarize_layers(repo_root: Path) -> list[LayerSummary]:
    store = GraphStore.open_for_repo(repo_root.resolve())
    try:
        node_counts = dict.fromkeys([layer.key for layer in LAYERS], 0)
        edge_counts = dict.fromkeys([layer.key for layer in LAYERS], 0)
        finding_counts = dict.fromkeys([layer.key for layer in LAYERS], 0)

        for row in store.conn.execute("SELECT kind, properties FROM nodes WHERE kind != 'File'"):
            props = json.loads(row["properties"] or "{}")
            if row["kind"] in {"Dependency", "DependencyManifest", "Vulnerability"}:
                node_counts["dependency"] += 1
            if row["kind"] == "Resource":
                node_counts["infrastructure"] += 1
            for prop, layer in PROPERTY_TO_LAYER.items():
                if props.get(prop):
                    node_counts[layer] += 1

        for row in store.conn.execute("SELECT kind FROM edges"):
            layer = EDGE_TO_LAYER.get(row["kind"])
            if layer:
                edge_counts[layer] += 1

        for row in store.conn.execute("SELECT rule_id, message, evidence FROM findings"):
            text = " ".join(str(row[key]) for key in row.keys()).lower()
            for layer in finding_counts:
                if layer in text:
                    finding_counts[layer] += 1
            if "sql" in text or "sink" in text or "execute" in text:
                finding_counts["sink"] += 1
            if "secret" in text or "password" in text or "token" in text:
                finding_counts["secrets"] += 1
            if "osv" in text or "npm" in text or "vulnerability" in text or "affected by" in text:
                finding_counts["dependency"] += 1
            if "iac" in text or "infrastructure" in text:
                finding_counts["infrastructure"] += 1

        return [
            LayerSummary(
                key=layer.key,
                label=layer.label,
                description=layer.description,
                node_count=node_counts[layer.key],
                edge_count=edge_counts[layer.key],
                finding_count=finding_counts[layer.key],
            )
            for layer in LAYERS
        ]
    finally:
        store.close()


def format_layer_summary(summaries: list[LayerSummary]) -> str:
    lines = ["Security layers:"]
    for item in summaries:
        lines.append(
            f"- {item.label}: {item.node_count} node(s), "
            f"{item.edge_count} edge(s), {item.finding_count} finding(s)"
        )
    return "\n".join(lines)
