"""Secret and credential exposure prioritization."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import (
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_EXPOSES_SECRET,
    EDGE_USES_SECRET,
)
from cybergraph.security.risk import RiskScore, score_risk


@dataclass(frozen=True)
class SecretExposure:
    function: str
    sink: str
    file_path: str
    line: int
    entrypoint_reachable: bool
    risk: RiskScore
    rationale: str


def find_secret_exposures(repo_root: Path) -> list[SecretExposure]:
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        secret_users = {
            row["source"]
            for row in store.conn.execute(
                "SELECT DISTINCT source FROM edges WHERE kind = ?", (EDGE_USES_SECRET,)
            )
        }
        entrypoints = {
            row["target"]
            for row in store.conn.execute(
                "SELECT target FROM edges WHERE kind = ?", (EDGE_EXPOSES_ENTRYPOINT,)
            )
        }
        callgraph: dict[str, set[str]] = {}
        for row in store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_CALLS_RESOLVED,)
        ):
            callgraph.setdefault(row["source"], set()).add(row["target"])
        reachable = _reachable_from_entrypoints(entrypoints, callgraph)

        exposures: list[SecretExposure] = []
        for row in store.conn.execute(
            """
            SELECT source, target, file_path, line
            FROM edges
            WHERE kind = ?
            ORDER BY source, target
            """,
            (EDGE_EXPOSES_SECRET,),
        ):
            function = row["source"]
            if function not in secret_users:
                continue
            entrypoint_reachable = function in reachable or function in entrypoints
            risk = _score_secret_exposure(row["target"], entrypoint_reachable)
            exposures.append(
                SecretExposure(
                    function=function,
                    sink=row["target"],
                    file_path=row["file_path"] or "",
                    line=row["line"] or 0,
                    entrypoint_reachable=entrypoint_reachable,
                    risk=risk,
                    rationale=(
                        "Secret value is passed to an exposure sink"
                        + (" reachable from an entrypoint." if entrypoint_reachable else ".")
                    ),
                )
            )
    finally:
        store.close()
    exposures.sort(key=lambda exposure: (-exposure.risk.score, exposure.function, exposure.sink))
    return exposures


def format_secret_exposures(exposures: list[SecretExposure]) -> str:
    if not exposures:
        return "No secret exposure paths found. Build the graph and check secret access patterns."
    lines = [f"Secret exposure risks: {len(exposures)}"]
    for exposure in exposures:
        location = f"{exposure.file_path}:{exposure.line}" if exposure.file_path else "-"
        reachable = "entrypoint-reachable" if exposure.entrypoint_reachable else "internal"
        lines.append(
            f"- [{exposure.risk.label.upper()} {exposure.risk.score}/100] "
            f"{exposure.function} -> {exposure.sink} ({reachable}) at {location}"
        )
        lines.append(f"  {exposure.rationale}")
        lines.append("  Fix: keep secrets out of logs, responses, subprocesses, and third-party calls.")
    return "\n".join(lines)


def _reachable_from_entrypoints(entrypoints: set[str], callgraph: dict[str, set[str]]) -> set[str]:
    reachable = set(entrypoints)
    queue: deque[str] = deque(entrypoints)
    while queue:
        node = queue.popleft()
        for nxt in callgraph.get(node, set()):
            if nxt in reachable:
                continue
            reachable.add(nxt)
            queue.append(nxt)
    return reachable


def _score_secret_exposure(sink: str, entrypoint_reachable: bool) -> RiskScore:
    lowered = sink.lower()
    external = any(token in lowered for token in ("response", "res.", "http", "fetch", "axios", "post"))
    process = any(token in lowered for token in ("exec", "process", "subprocess", "command"))
    return score_risk(
        reachability=1.0 if entrypoint_reachable else 0.55,
        exposure=1.0 if external or process else 0.75,
        exploitability=0.8,
        impact=0.9,
        controls=0.0,
        confidence="high" if entrypoint_reachable else "medium",
    )
