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

import json
from collections import deque
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED
from cybergraph.config import load_config
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import (
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_REACHES_SINK,
    EDGE_SANITIZES,
    EDGE_TAINTS,
)
from cybergraph.security.remediation import remediation_for_sink
from cybergraph.security.risk import RiskScore, score_risk

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
_RANK_CONF = {3: "high", 2: "medium", 1: "low"}


@dataclass(frozen=True)
class AttackPath:
    entrypoint: str
    sink: str
    nodes: tuple[str, ...]
    confidence: str = "high"
    sanitized: bool = False
    data_reachable: bool = False
    taint_sources: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    risk: RiskScore | None = None


def find_attack_paths(
    repo_root: Path,
    max_depth: int = 8,
    limit: int = 20,
    interprocedural: bool = True,
    apply_suppressions: bool = True,
    suppression_root: Path | None = None,
) -> list[AttackPath]:
    """Find entrypoint-to-sink attack paths for ``repo_root``.

    **New behaviour.** Until this parameter existed, ``find_attack_paths``
    applied no suppression at all on any surface -- every caller saw every
    path. ``apply_suppressions`` now defaults to ``True``, so the ranked and
    actionable surfaces (CLI ``attack-paths``, top risks, PR review, cloud,
    Strix scope, ``analyze``) *hide* paths they previously showed. That is a
    deliberate change of output, not a reordering of an existing filter.

    ``apply_suppressions`` drops paths whose every file is covered by
    ``[suppressions] paths`` in ``.cybergraph.toml``, and it drops them
    **before** ``limit`` is applied, so accepted fixture noise cannot starve
    the real results behind it.

    Pass ``apply_suppressions=False`` on exploration and evidence surfaces
    (graph export, visualisation, MCP explain, grounded RAG, triage evidence):
    suppressions hide *findings*, but the graph still keeps the underlying
    edges so reviewers can inspect the real code path. Note that
    ``security/investigate.py`` deliberately keeps the suppressing default --
    the call site there feeds ``collect_top_risks``, which is a ranking.

    ``suppression_root`` loads the suppression config from a *different*
    directory than the graph being queried. Callers that materialise a tree
    from git (``security/review.py``) must pass the real repository root, so
    both sides of a diff are scanned under one configuration: configuration is
    not part of a code delta, and a config-only difference must never render
    as an added or removed attack path.
    """
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

        taints = _load_taints(store)

        config_root = suppression_root if suppression_root is not None else repo_root
        patterns = load_config(config_root).suppressed_paths if apply_suppressions else ()
        return _traverse(
            entrypoints, sinks, sanitizers, callgraph, taints, max_depth, limit, patterns
        )
    finally:
        store.close()


def _traverse(
    entrypoints: list[str],
    sinks: dict[str, list[str]],
    sanitizers: set[str],
    callgraph: dict[str, list[tuple[str, str]]],
    taints: dict[tuple[str, str], tuple[str, ...]],
    max_depth: int,
    limit: int,
    patterns: tuple[str, ...] = (),
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
                if patterns and path_is_suppressed(path + (sink_name,), patterns):
                    continue
                taint_sources = taints.get((node, sink_name), ())
                risk = _score_attack_path(
                    sink_name, bool(taint_sources), sanitized, _RANK_CONF[conf_rank]
                )
                reasons = _path_reasons(
                    path=path,
                    sink_name=sink_name,
                    confidence=_RANK_CONF[conf_rank],
                    sanitized=sanitized,
                    taint_sources=taint_sources,
                    interprocedural=bool(callgraph),
                )
                paths.append(
                    AttackPath(
                        entrypoint=entry,
                        sink=sink_name,
                        nodes=path + (sink_name,),
                        confidence=_RANK_CONF[conf_rank],
                        sanitized=sanitized,
                        data_reachable=bool(taint_sources),
                        taint_sources=taint_sources,
                        reasons=reasons,
                        risk=risk,
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


def path_is_suppressed(nodes: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    """Suppress only when every file the path touches is suppressed.

    Conservative on purpose: a path crossing from suppressed fixture code into
    real application code is still reported. Node keys that carry no file
    component (bare sink names such as ``subprocess.run``) are ignored, and a
    path with no identifiable file is never suppressed -- an unknown file is
    treated as unsuppressed, so incomplete information abstains from hiding
    rather than hiding silently.

    Public because a caller that wants to *count* what the config hides
    (``security/review.py``) must ask the same predicate that does the hiding.
    A second copy of this rule could disagree with it, and the direction it
    would disagree in is the dangerous one.
    """
    files = {node.split("::", 1)[0] for node in nodes if "::" in node}
    if not files:
        return False
    return all(any(fnmatch(file, pattern) for pattern in patterns) for file in files)


def format_attack_paths(paths: list[AttackPath]) -> str:
    if not paths:
        return (
            "No entrypoint-to-sink paths found yet. "
            "Build the graph and check route decorators/sink calls."
        )
    lines = ["Potential attack paths:"]
    for path in paths:
        flags = f"confidence={path.confidence}"
        if path.sanitized:
            flags += ", validated"
        flags += ", data=tainted" if path.data_reachable else ", data=structural-only"
        if path.risk:
            flags += f", risk={path.risk.label}/{path.risk.score}"
        lines.append(f"- {path.entrypoint} -> {path.sink} ({flags})")
        lines.append(f"  path: {' -> '.join(path.nodes)}")
        if path.taint_sources:
            lines.append(f"  user input: {', '.join(path.taint_sources)}")
        if path.reasons:
            lines.append(f"  why: {'; '.join(path.reasons)}")
        lines.append(f"  fix: {remediation_for_sink(path.sink)}")
    return "\n".join(lines)


def _score_attack_path(
    sink_name: str,
    data_reachable: bool,
    sanitized: bool,
    confidence: str,
) -> RiskScore:
    lowered = sink_name.lower()
    impact = (
        0.9 if any(token in lowered for token in ("exec", "shell", "eval", "command")) else 0.75
    )
    if any(token in lowered for token in ("execute", "query", "sql")):
        impact = max(impact, 0.85)
    if any(token in lowered for token in ("open", "read", "write", "file")):
        impact = max(impact, 0.7)
    return score_risk(
        reachability=1.0 if data_reachable else 0.6,
        exposure=1.0,
        exploitability=0.85 if data_reachable else 0.45,
        impact=impact,
        controls=0.35 if sanitized else 0.0,
        confidence=confidence,
    )


def _load_taints(store: GraphStore) -> dict[tuple[str, str], tuple[str, ...]]:
    """Map (function, sink) pairs to user-controlled data-flow source labels."""
    source_names = {
        row["key"]: row["name"]
        for row in store.conn.execute(
            "SELECT key, name FROM nodes WHERE kind IN ('Input', 'DataFlow')"
        )
    }
    taints: dict[tuple[str, str], set[str]] = {}
    for row in store.conn.execute(
        "SELECT source, target, properties FROM edges WHERE kind = ?", (EDGE_TAINTS,)
    ):
        props = _loads(row["properties"])
        function = props.get("function")
        if not function:
            continue
        label = source_names.get(row["source"], row["source"])
        taints.setdefault((function, row["target"]), set()).add(label)
    return {key: tuple(sorted(values)) for key, values in taints.items()}


def _path_reasons(
    path: tuple[str, ...],
    sink_name: str,
    confidence: str,
    sanitized: bool,
    taint_sources: tuple[str, ...],
    interprocedural: bool,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if interprocedural and len(path) > 1:
        reasons.append("follows resolved calls across functions")
    else:
        reasons.append("sink is directly reachable from the entrypoint scope")
    if taint_sources:
        reasons.append(f"user-controlled data reaches `{sink_name}`")
    else:
        reasons.append("no user-controlled argument evidence was found for the sink")
    if sanitized:
        reasons.append("a sanitizer or validation barrier appears on the path")
    reasons.append(f"confidence is {confidence}")
    return tuple(reasons)


def _confidence_from_properties(raw: str | None) -> str:
    if not raw:
        return "high"

    try:
        props = json.loads(raw)
    except (TypeError, ValueError):
        return "high"
    return props.get("confidence", "high") if isinstance(props, dict) else "high"


def _loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
