"""Security delta review helpers."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.config import CONFIG_FILE, load_config
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths


@dataclass(frozen=True)
class SecurityReview:
    base: str
    changed_files: tuple[str, ...]
    finding_count: int
    changed_entrypoints: tuple[str, ...]
    changed_sink_edges: tuple[str, ...]
    attack_path_count: int
    risk_deltas: tuple[RiskDelta, ...] = ()
    #: Suppression-config differences between ``base`` and the working tree,
    #: reported on their own terms because configuration is not code.
    suppression_notes: tuple[str, ...] = ()
    #: Reachable risks in changed files that the current suppression config
    #: hides from the deltas above. They are hidden, not fixed.
    suppressed_risk_count: int = 0


@dataclass(frozen=True)
class RiskDelta:
    status: str
    signature: str
    entrypoint: str
    sink: str
    risk_score: int
    risk_label: str
    data_reachable: bool
    files: tuple[str, ...]


def review_security_delta(repo_root: Path, base: str = "HEAD~1") -> SecurityReview:
    """Review security-relevant graph evidence for files changed since a git ref."""
    repo_root = repo_root.resolve()
    changed_files = tuple(_changed_files(repo_root, base))

    # Keep review deterministic: rebuild from current working tree before querying.
    build_graph(repo_root)
    store = GraphStore.open_for_repo(repo_root)
    try:
        placeholders = ",".join("?" for _ in changed_files)
        findings = 0
        entrypoints: tuple[str, ...] = ()
        sinks: tuple[str, ...] = ()
        if changed_files:
            findings = store.conn.execute(
                f"SELECT COUNT(*) FROM findings WHERE file_path IN ({placeholders})",
                changed_files,
            ).fetchone()[0]
            entrypoints = tuple(
                row["target"]
                for row in store.conn.execute(
                    f"""
                    SELECT target FROM edges
                    WHERE kind = 'EXPOSES_ENTRYPOINT' AND file_path IN ({placeholders})
                    ORDER BY target
                    """,
                    changed_files,
                )
            )
            sinks = tuple(
                f"{row['source']} -> {row['target']}"
                for row in store.conn.execute(
                    f"""
                    SELECT source, target FROM edges
                    WHERE kind = 'REACHES_SINK' AND file_path IN ({placeholders})
                    ORDER BY source, target
                    """,
                    changed_files,
                )
            )
    finally:
        store.close()

    paths = find_attack_paths(repo_root)
    changed_set = set(changed_files)
    changed_path_count = sum(
        1
        for path in paths
        if any(node.split("::", 1)[0] in changed_set for node in path.nodes)
    )
    # Both sides of the delta are scanned under the *working tree's* suppression
    # config. A PR delta compares code; a config difference between base and head
    # is not a code change and must never be rendered as one.
    current_patterns = load_config(repo_root).suppressed_paths
    current_risks = _risk_items(repo_root, changed_set)
    base_risks: dict[str, RiskDelta] = {}
    base_patterns: tuple[str, ...] | None = None
    if changed_files:
        base_risks, base_patterns = _base_scan(repo_root, base, changed_set)
    risk_deltas = tuple(_classify_risk_deltas(current_risks, base_risks))

    suppression_notes: tuple[str, ...] = ()
    suppressed_risk_count = 0
    if changed_files:
        suppression_notes = _suppression_notes(repo_root, current_patterns, base_patterns)
        if current_patterns:
            unsuppressed = _risk_items(repo_root, changed_set, apply_suppressions=False)
            suppressed_risk_count = len(set(unsuppressed) - set(current_risks))

    return SecurityReview(
        base=base,
        changed_files=changed_files,
        finding_count=findings,
        changed_entrypoints=entrypoints,
        changed_sink_edges=sinks,
        attack_path_count=changed_path_count,
        risk_deltas=risk_deltas,
        suppression_notes=suppression_notes,
        suppressed_risk_count=suppressed_risk_count,
    )


def format_security_review(review: SecurityReview) -> str:
    if not review.changed_files:
        return f"No changed files found against {review.base}."

    risk = "high" if review.attack_path_count or review.finding_count > 3 else "medium"
    if (
        review.finding_count == 0
        and not review.changed_sink_edges
        and not review.changed_entrypoints
    ):
        risk = "low"

    lines = [
        f"Security review against {review.base}",
        f"Risk: {risk}",
        f"Changed files: {len(review.changed_files)}",
        f"Findings in changed files: {review.finding_count}",
        f"Changed entrypoints: {len(review.changed_entrypoints)}",
        f"Changed sensitive sink edges: {len(review.changed_sink_edges)}",
        f"Changed attack paths: {review.attack_path_count}",
        f"Risk deltas: {len(review.risk_deltas)}",
    ]
    if review.suppressed_risk_count:
        lines.append(
            f"Reachable risks hidden by suppression config: {review.suppressed_risk_count} "
            "(hidden, not fixed)"
        )
    if review.suppression_notes:
        lines.append("")
        lines.append("Suppression config (configuration, not a code change):")
        lines.extend(f"- {note}" for note in review.suppression_notes)
    if review.risk_deltas:
        lines.append("")
        lines.append("Reachable risk deltas:")
        for delta in review.risk_deltas[:10]:
            lines.append(
                f"- {delta.status}: {delta.entrypoint} -> {delta.sink} "
                f"({delta.risk_label}/{delta.risk_score}, data_reachable={delta.data_reachable})"
            )
    if review.changed_entrypoints:
        lines.append("")
        lines.append("Entrypoints:")
        lines.extend(f"- {entrypoint}" for entrypoint in review.changed_entrypoints[:10])
    if review.changed_sink_edges:
        lines.append("")
        lines.append("Sensitive sink edges:")
        lines.extend(f"- {sink}" for sink in review.changed_sink_edges[:10])
    return "\n".join(lines)


def _changed_files(repo_root: Path, base: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base, "--"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def _risk_items(
    repo_root: Path,
    changed_files: set[str],
    suppression_root: Path | None = None,
    apply_suppressions: bool = True,
) -> dict[str, RiskDelta]:
    """Reachable risks in ``repo_root`` that touch ``changed_files``.

    ``suppression_root`` decouples *where the code lives* from *which config
    governs it*. The base side of a review is a git tree materialised into a
    temporary directory that has no config of its own (or, worse, a stale one),
    so it must be scanned under the current repository's config -- otherwise a
    suppression that only exists on one side reads as a code change.
    """
    items: dict[str, RiskDelta] = {}
    for path in find_attack_paths(
        repo_root,
        limit=100,
        apply_suppressions=apply_suppressions,
        suppression_root=suppression_root,
    ):
        files = tuple(dict.fromkeys(node.split("::", 1)[0] for node in path.nodes if "::" in node))
        if changed_files and not any(file in changed_files for file in files):
            continue
        signature = f"{path.entrypoint}->{path.sink}|{'->'.join(path.nodes)}"
        risk_score = path.risk.score if path.risk else 0
        risk_label = path.risk.label if path.risk else "unknown"
        items[signature] = RiskDelta(
            status="unchanged",
            signature=signature,
            entrypoint=path.entrypoint,
            sink=path.sink,
            risk_score=risk_score,
            risk_label=risk_label,
            data_reachable=path.data_reachable,
            files=files,
        )
    return items


def _base_scan(
    repo_root: Path,
    base: str,
    changed_files: set[str],
) -> tuple[dict[str, RiskDelta], tuple[str, ...] | None]:
    """Scan the ``base`` tree and read the suppression config it carried.

    The risks come back filtered by the *current* repository config
    (``suppression_root=repo_root``); the returned patterns are the base tree's
    own, used only to describe a config change, never to filter. ``None``
    patterns mean the base tree could not be materialised, so nothing is known
    and nothing is claimed.
    """
    with tempfile.TemporaryDirectory(prefix="cybergraph-base-") as temp:
        temp_root = Path(temp)
        if not _materialize_git_ref(repo_root, base, temp_root):
            return {}, None
        base_patterns = load_config(temp_root).suppressed_paths
        build_graph(temp_root)
        return _risk_items(temp_root, changed_files, suppression_root=repo_root), base_patterns


def _suppression_notes(
    repo_root: Path,
    current: tuple[str, ...],
    base: tuple[str, ...] | None,
) -> tuple[str, ...]:
    """Describe the suppression config on its own terms.

    A PR that genuinely adds a suppression should say so: "added: legacy/**" is
    useful, "removed: legacy/app.py::run0 -> subprocess.run" is a lie. An
    untracked config is not part of the change at all and is labelled as the
    local override it is.
    """
    if base is None:
        return ()
    if current and not _is_tracked(repo_root, CONFIG_FILE):
        return (
            f"local: {CONFIG_FILE} is untracked, so its suppressions are a local "
            f"override rather than part of this change ({', '.join(current)})",
        )
    notes = [f"added: {pattern}" for pattern in current if pattern not in base]
    notes += [f"removed: {pattern}" for pattern in base if pattern not in current]
    return tuple(notes)


def _is_tracked(repo_root: Path, rel_path: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--", rel_path],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return bool(result.stdout.strip())


def _classify_risk_deltas(
    current: dict[str, RiskDelta],
    base: dict[str, RiskDelta],
) -> list[RiskDelta]:
    deltas: list[RiskDelta] = []
    for signature, item in current.items():
        previous = base.get(signature)
        if previous is None:
            deltas.append(_with_status(item, "added"))
        elif item.risk_score > previous.risk_score or (
            item.data_reachable and not previous.data_reachable
        ):
            deltas.append(_with_status(item, "worsened"))
        else:
            deltas.append(_with_status(item, "unchanged"))
    for signature, item in base.items():
        if signature not in current:
            deltas.append(_with_status(item, "removed"))
    order = {"added": 0, "worsened": 1, "removed": 2, "unchanged": 3}
    return sorted(deltas, key=lambda d: (order.get(d.status, 9), -d.risk_score, d.signature))


def _with_status(item: RiskDelta, status: str) -> RiskDelta:
    return RiskDelta(
        status=status,
        signature=item.signature,
        entrypoint=item.entrypoint,
        sink=item.sink,
        risk_score=item.risk_score,
        risk_label=item.risk_label,
        data_reachable=item.data_reachable,
        files=item.files,
    )


def _materialize_git_ref(repo_root: Path, ref: str, output: Path) -> bool:
    try:
        files = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", ref],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    for rel in files:
        rel = rel.strip()
        if not rel:
            continue
        try:
            blob = subprocess.run(
                ["git", "show", f"{ref}:{rel}"],
                cwd=repo_root,
                check=True,
                capture_output=True,
            ).stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    return True
