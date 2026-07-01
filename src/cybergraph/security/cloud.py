"""Correlate cloud/IaC resources with application code paths."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.ontology import EDGE_USES_RESOURCE
from cybergraph.security.risk import RiskScore, score_risk


@dataclass(frozen=True)
class CloudCodePath:
    resource: str
    code: str
    sink: str
    public_exposure: bool
    privileged: bool
    risk: RiskScore
    evidence: tuple[str, ...]


def find_cloud_code_paths(repo_root: Path) -> list[CloudCodePath]:
    repo_root = Path(repo_root).resolve()
    attack_paths = find_attack_paths(repo_root, limit=100)
    sink_by_code: dict[str, str] = {}
    for path in attack_paths:
        for node in path.nodes:
            if "::" in node:
                sink_by_code.setdefault(node, path.sink)

    store = GraphStore.open_for_repo(repo_root)
    try:
        resources = _resources(store)
        rows = store.conn.execute(
            "SELECT source, target, properties FROM edges WHERE kind = ?", (EDGE_USES_RESOURCE,)
        ).fetchall()
    finally:
        store.close()

    results: list[CloudCodePath] = []
    for row in rows:
        resource = resources.get(row["target"])
        if not resource:
            continue
        props = resource["props"]
        public = bool(props.get("public_exposure"))
        privileged = bool(props.get("privileged"))
        sink = sink_by_code.get(row["source"], "")
        if not (public or privileged or sink):
            continue
        risk = score_risk(
            reachability=1.0 if sink else 0.65,
            exposure=1.0 if public else 0.55,
            exploitability=0.75 if sink else 0.45,
            impact=0.9 if privileged else 0.75,
            controls=0.0,
            confidence="medium",
        )
        edge_props = _loads(row["properties"])
        results.append(
            CloudCodePath(
                resource=resource["name"],
                code=row["source"],
                sink=sink,
                public_exposure=public,
                privileged=privileged,
                risk=risk,
                evidence=tuple(
                    part for part in (f"resource hint `{edge_props.get('hint', '')}`", sink) if part
                ),
            )
        )
    results.sort(key=lambda item: (-item.risk.score, item.resource, item.code))
    return results


def format_cloud_code_paths(paths: list[CloudCodePath]) -> str:
    if not paths:
        return "No cloud-to-code correlations found. Build the graph and ensure code references IaC resource names."
    lines = [f"Cloud-to-code correlations: {len(paths)}"]
    for path in paths:
        exposure = "public" if path.public_exposure else "internal"
        privilege = ", privileged" if path.privileged else ""
        sink = f", reaches {path.sink}" if path.sink else ""
        lines.append(
            f"- [{path.risk.label.upper()} {path.risk.score}/100] "
            f"{path.resource} -> {path.code} ({exposure}{privilege}{sink})"
        )
        if path.evidence:
            lines.append(f"  evidence: {', '.join(path.evidence)}")
    return "\n".join(lines)


def _resources(store: GraphStore) -> dict[str, dict]:
    resources: dict[str, dict] = {}
    for row in store.conn.execute("SELECT key, name, properties FROM nodes WHERE kind = 'Resource'"):
        resources[row["key"]] = {"name": row["name"], "props": _loads(row["properties"])}
    return resources


def _loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
