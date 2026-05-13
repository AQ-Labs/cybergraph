"""Security delta review helpers."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from cybergraph.build import build_graph
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

    return SecurityReview(
        base=base,
        changed_files=changed_files,
        finding_count=findings,
        changed_entrypoints=entrypoints,
        changed_sink_edges=sinks,
        attack_path_count=changed_path_count,
    )


def format_security_review(review: SecurityReview) -> str:
    if not review.changed_files:
        return f"No changed files found against {review.base}."

    risk = "high" if review.attack_path_count or review.finding_count > 3 else "medium"
    if review.finding_count == 0 and not review.changed_sink_edges and not review.changed_entrypoints:
        risk = "low"

    lines = [
        f"Security review against {review.base}",
        f"Risk: {risk}",
        f"Changed files: {len(review.changed_files)}",
        f"Findings in changed files: {review.finding_count}",
        f"Changed entrypoints: {len(review.changed_entrypoints)}",
        f"Changed sensitive sink edges: {len(review.changed_sink_edges)}",
        f"Changed attack paths: {review.attack_path_count}",
    ]
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
