"""Security delta review helpers."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cybergraph.analysis import is_ignored_path, is_supported_source
from cybergraph.build import build_graph
from cybergraph.config import CONFIG_FILE, CyberGraphConfig, load_config
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import AttackPath, find_attack_paths, path_is_suppressed

#: Traversal cap for the two scans whose difference *is* the delta. Both sides
#: use it, so neither side is truncated relative to the other.
_DELTA_PATH_LIMIT = 100
#: Traversal cap for the accounting scan that measures what the config hides.
#: Deliberately larger than the delta cap: this number is only ever used to
#: state blast radius, and understating it understates the risk being accepted.
_HIDDEN_PATH_LIMIT = 1000

#: The config keys that decide what either scan can *see*. Each is reported on
#: its own terms; none of them may reach the reviewer as a code delta.
_CONFIG_KEYS: tuple[tuple[str, str], ...] = (
    ("[suppressions] paths", "suppressed_paths"),
    ("[ignore] paths", "ignored_paths"),
    ("[security] sinks", "custom_sinks"),
)


@dataclass(frozen=True)
class SecurityReview:
    base: str
    changed_files: tuple[str, ...]
    finding_count: int
    changed_entrypoints: tuple[str, ...]
    changed_sink_edges: tuple[str, ...]
    attack_path_count: int
    risk_deltas: tuple[RiskDelta, ...] = ()
    #: Differences in the ``.cybergraph.toml`` keys that govern what the scans
    #: can see, between ``base`` and the working tree. Reported on their own
    #: terms because configuration is not code.
    config_notes: tuple[str, ...] = ()
    #: Reachable risks in changed files that the current suppression config
    #: hides from the deltas above. They are hidden, not fixed.
    suppressed_risk_count: int = 0
    #: ``True`` when the accounting scan hit ``_HIDDEN_PATH_LIMIT``, making
    #: ``suppressed_risk_count`` a lower bound rather than the true count.
    suppressed_risk_count_capped: bool = False
    #: Changed files that ``[ignore] paths`` removed from the analysis on both
    #: sides. Nothing was scanned there, so nothing there can be called fixed.
    ignored_changed_files: tuple[str, ...] = ()


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
    # Both sides of the delta are scanned under the *working tree's* config --
    # every key of it, not just the suppressions. A PR delta compares code; a
    # config difference between base and head is not a code change and must
    # never be rendered as one.
    current_config = load_config(repo_root)
    current_risks = _risk_items(repo_root, changed_set)
    base_risks: dict[str, RiskDelta] = {}
    base_config: CyberGraphConfig | None = None
    if changed_files:
        base_risks, base_config = _base_scan(repo_root, base, changed_set)
    risk_deltas = tuple(_classify_risk_deltas(current_risks, base_risks))

    config_notes: tuple[str, ...] = ()
    suppressed_risk_count = 0
    capped = False
    ignored_changed_files: tuple[str, ...] = ()
    if changed_files:
        config_notes = _config_notes(repo_root, current_config, base_config)
        suppressed_risk_count, capped = _hidden_risk_count(
            repo_root, changed_set, current_config.suppressed_paths
        )
        ignored_changed_files = _ignored_changed_files(changed_files, current_config.ignored_paths)

    return SecurityReview(
        base=base,
        changed_files=changed_files,
        finding_count=findings,
        changed_entrypoints=entrypoints,
        changed_sink_edges=sinks,
        attack_path_count=changed_path_count,
        risk_deltas=risk_deltas,
        config_notes=config_notes,
        suppressed_risk_count=suppressed_risk_count,
        suppressed_risk_count_capped=capped,
        ignored_changed_files=ignored_changed_files,
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
        count = (
            f"at least {review.suppressed_risk_count} (scan capped at {_HIDDEN_PATH_LIMIT} paths)"
            if review.suppressed_risk_count_capped
            else str(review.suppressed_risk_count)
        )
        lines.append(f"Reachable risks hidden by suppression config: {count} (hidden, not fixed)")
    if review.ignored_changed_files:
        lines.append(
            f"Changed files excluded from analysis by [ignore] paths: "
            f"{len(review.ignored_changed_files)} (not analysed, not fixed)"
        )
        lines.extend(f"- {file}" for file in review.ignored_changed_files[:10])
    if review.config_notes:
        lines.append("")
        lines.append("Config differences (configuration, not a code change; none of it is a fix):")
        lines.extend(f"- {note}" for note in review.config_notes)
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
    limit: int = _DELTA_PATH_LIMIT,
) -> dict[str, RiskDelta]:
    """Reachable risks in ``repo_root`` that touch ``changed_files``.

    ``suppression_root`` decouples *where the code lives* from *which config
    governs it*. The base side of a review is a git tree materialised into a
    temporary directory that has no config of its own (or, worse, a stale one),
    so it must be scanned under the current repository's config -- otherwise a
    suppression that only exists on one side reads as a code change. Its
    counterpart for the graph build is ``build_graph(config_root=...)``.
    """
    paths = find_attack_paths(
        repo_root,
        limit=limit,
        apply_suppressions=apply_suppressions,
        suppression_root=suppression_root,
    )
    return _items_for(paths, changed_files)


def _items_for(paths: list[AttackPath], changed_files: set[str]) -> dict[str, RiskDelta]:
    items: dict[str, RiskDelta] = {}
    for path in paths:
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
) -> tuple[dict[str, RiskDelta], CyberGraphConfig | None]:
    """Scan the ``base`` tree and read the config it carried.

    The base tree is *built* under the current repository's config
    (``config_root=repo_root``) and *queried* under it too
    (``suppression_root=repo_root``), so both sides of the delta see the same
    files, the same sinks and the same suppressions. The returned config is the
    base tree's own, used only to describe a config change and never to filter.
    ``None`` means the base tree could not be materialised, so nothing is known
    and nothing is claimed.
    """
    with tempfile.TemporaryDirectory(prefix="cybergraph-base-") as temp:
        temp_root = Path(temp)
        if not _materialize_git_ref(repo_root, base, temp_root):
            return {}, None
        base_config = load_config(temp_root)
        build_graph(temp_root, config_root=repo_root)
        return _risk_items(temp_root, changed_files, suppression_root=repo_root), base_config


def _config_notes(
    repo_root: Path,
    current: CyberGraphConfig,
    base: CyberGraphConfig | None,
) -> tuple[str, ...]:
    """Describe the scan-governing config on its own terms.

    A PR that genuinely changes one of these keys should say so: "[ignore]
    paths added by this change: legacy/**" is useful, "removed:
    legacy/app.py::run0 -> subprocess.run" is a lie -- the sink is still there
    and still live. An untracked config is not part of the change at all and is
    labelled as the local override it is, per key, because otherwise its whole
    content would be misread as something this PR added.

    The wording deliberately avoids the bare ``added:``/``removed:`` tokens the
    risk deltas use. A reviewer -- or a grep -- must be able to tell a
    configuration line from a claim about code at a glance.
    """
    if base is None:
        return ()
    tracked = _is_tracked(repo_root, CONFIG_FILE)
    notes: list[str] = []
    for label, attribute in _CONFIG_KEYS:
        current_values: tuple[str, ...] = getattr(current, attribute)
        base_values: tuple[str, ...] = getattr(base, attribute)
        if current_values and not tracked:
            notes.append(
                f"local override: {CONFIG_FILE} is untracked, so its {label} setting is "
                f"not part of this change ({', '.join(current_values)})"
            )
            continue
        notes += [
            f"{label} added by this change: {value}"
            for value in current_values
            if value not in base_values
        ]
        notes += [
            f"{label} dropped by this change: {value}"
            for value in base_values
            if value not in current_values
        ]
    return tuple(notes)


def _hidden_risk_count(
    repo_root: Path,
    changed_files: set[str],
    patterns: tuple[str, ...],
) -> tuple[int, bool]:
    """Count reachable risks in changed files that ``patterns`` hide.

    Counted directly rather than by differencing two capped scans: with the old
    set difference the number was bounded by the *delta* scan's limit and, worse,
    a repo whose real risks already filled that limit reported zero hidden ones.
    One unsuppressed scan is taken at a deliberately larger cap and each path is
    put to :func:`path_is_suppressed` -- the same fail-closed predicate that does
    the hiding. The bool says the cap was reached, so the caller states a lower
    bound instead of a wrong exact number.
    """
    if not patterns:
        return 0, False
    paths = find_attack_paths(repo_root, limit=_HIDDEN_PATH_LIMIT, apply_suppressions=False)
    hidden = [path for path in paths if path_is_suppressed(path.nodes, patterns)]
    return len(_items_for(hidden, changed_files)), len(paths) >= _HIDDEN_PATH_LIMIT


def _ignored_changed_files(
    changed_files: tuple[str, ...],
    ignored_paths: tuple[str, ...],
) -> tuple[str, ...]:
    """Changed source files that ``[ignore] paths`` kept out of both scans.

    The suppression path has ``suppressed_risk_count`` to say "hidden, not
    fixed". ``[ignore] paths`` needs its own answer, because a file the
    collector never opened produces no nodes, no edges and therefore no risk to
    count -- the silence is total. Naming the files is the honest equivalent:
    the review states where it did not look. Non-source files are left out;
    the analysis would not have read them either way, so listing them would
    only be noise.
    """
    if not ignored_paths:
        return ()
    return tuple(
        file
        for file in changed_files
        if is_supported_source(Path(file)) and is_ignored_path(file, ignored_paths)
    )


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
