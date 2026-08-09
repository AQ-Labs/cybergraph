"""Pull request comment generation."""

from __future__ import annotations

from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.layers import summarize_layers
from cybergraph.security.review import review_security_delta


def generate_pr_comment(repo_root: Path, base: str = "HEAD~1") -> str:
    repo_root = repo_root.resolve()
    review = review_security_delta(repo_root, base=base)
    layers = summarize_layers(repo_root)
    store = GraphStore.open_for_repo(repo_root)
    try:
        counts = store.counts()
        top_findings = store.conn.execute(
            """
            SELECT rule_id, severity, message, file_path, line_start
            FROM findings
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                file_path,
                line_start
            LIMIT 5
            """
        ).fetchall()
    finally:
        store.close()

    risk = _risk(review)
    lines = [
        "<!-- cybergraph-pr-comment -->",
        "## CyberGraph Security Review",
        "",
        f"**Risk:** `{risk}`",
        "",
        "### What Changed",
        "",
        _change_summary(review),
        "",
        "### Why It Matters",
        "",
        _risk_summary(review),
        "",
        "### What To Check Next",
        "",
        *_checklist(review),
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Changed files | {len(review.changed_files)} |",
        f"| Findings in changed files | {review.finding_count} |",
        f"| Changed entrypoints | {len(review.changed_entrypoints)} |",
        f"| Changed sink edges | {len(review.changed_sink_edges)} |",
        f"| Changed attack paths | {review.attack_path_count} |",
        f"| Risk deltas | {len(review.risk_deltas)} |",
        f"| Total graph nodes | {counts['nodes']} |",
        f"| Total graph edges | {counts['edges']} |",
        f"| Total findings | {counts['findings']} |",
        "",
        "### Layer Summary",
        "",
        "| Layer | Nodes | Edges | Findings |",
        "|---|---:|---:|---:|",
    ]
    for layer in layers:
        if layer.node_count or layer.edge_count or layer.finding_count:
            lines.append(
                f"| {layer.label} | {layer.node_count} | {layer.edge_count} "
                f"| {layer.finding_count} |"
            )

    if review.changed_entrypoints:
        lines.extend(["", "### Changed Entrypoints", ""])
        lines.extend(f"- `{entrypoint}`" for entrypoint in review.changed_entrypoints[:10])
    if review.changed_sink_edges:
        lines.extend(["", "### Changed Sink Edges", ""])
        lines.extend(f"- `{sink}`" for sink in review.changed_sink_edges[:10])
    if review.risk_deltas:
        lines.extend(["", "### Reachable Risk Deltas", ""])
        for delta in review.risk_deltas[:10]:
            data = "data-reachable" if delta.data_reachable else "structural"
            lines.append(
                f"- `{delta.status}` `{delta.risk_label}` {delta.risk_score}/100 "
                f"`{delta.entrypoint}` -> `{delta.sink}` ({data})"
            )
    if review.config_notes or review.suppressed_risk_count or review.ignored_changed_files:
        # Configuration is not code. Both sides of the delta above were scanned
        # under the same (current) config -- suppressions, ignores and custom
        # sinks alike -- so a config change is reported here rather than
        # masquerading as an added or removed attack path.
        lines.extend(["", "### Scan Configuration (not a code change)", ""])
        if review.suppressed_risk_count:
            count = (
                f"at least {review.suppressed_risk_count}"
                if review.suppressed_risk_count_capped
                else str(review.suppressed_risk_count)
            )
            lines.append(
                f"- {count} reachable risk(s) in changed files are "
                "**hidden by suppression config, not fixed**"
            )
        if review.ignored_changed_files:
            listed = ", ".join(f"`{file}`" for file in review.ignored_changed_files[:10])
            lines.append(
                f"- {len(review.ignored_changed_files)} changed file(s) were "
                f"**excluded from analysis by `[ignore] paths`, not analysed**: {listed}"
            )
        lines.extend(f"- {note}" for note in review.config_notes)
    if top_findings:
        lines.extend(["", "### Top Findings", ""])
        for finding in top_findings:
            location = (
                f"{finding['file_path']}:{finding['line_start']}" if finding["file_path"] else "-"
            )
            lines.append(
                f"- `{finding['severity']}` `{finding['rule_id']}` at `{location}`: "
                f"{finding['message']}"
            )
    lines.extend(
        [
            "",
            "Artifacts: download `cybergraph-report.html` from this workflow run "
            "for the full report.",
            "",
            "<sub>Generated by CyberGraph.</sub>",
        ]
    )
    return "\n".join(lines)


def write_pr_comment(repo_root: Path, output: Path, base: str = "HEAD~1") -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(generate_pr_comment(repo_root, base=base), encoding="utf-8")
    return output


def _risk(review) -> str:
    if any(
        delta.status in {"added", "worsened"} and delta.risk_score >= 70
        for delta in review.risk_deltas
    ):
        return "high"
    if review.attack_path_count or review.finding_count > 3:
        return "high"
    if review.finding_count or review.changed_sink_edges or review.changed_entrypoints:
        return "medium"
    return "low"


def _change_summary(review) -> str:
    parts: list[str] = []
    if review.changed_files:
        parts.append(f"{len(review.changed_files)} changed file(s)")
    if review.changed_entrypoints:
        parts.append(f"{len(review.changed_entrypoints)} entrypoint(s)")
    if review.changed_sink_edges:
        parts.append(f"{len(review.changed_sink_edges)} sensitive sink edge(s)")
    if review.finding_count:
        parts.append(f"{review.finding_count} finding(s) in changed files")
    added = sum(1 for delta in review.risk_deltas if delta.status == "added")
    worsened = sum(1 for delta in review.risk_deltas if delta.status == "worsened")
    removed = sum(1 for delta in review.risk_deltas if delta.status == "removed")
    if added:
        parts.append(f"{added} added reachable risk(s)")
    if worsened:
        parts.append(f"{worsened} worsened reachable risk(s)")
    if removed:
        parts.append(f"{removed} removed reachable risk(s)")
    if not parts:
        return "No security-relevant graph changes were detected in this diff."
    return "CyberGraph detected " + ", ".join(parts) + "."


def _risk_summary(review) -> str:
    added_or_worsened = [d for d in review.risk_deltas if d.status in {"added", "worsened"}]
    if added_or_worsened:
        top = added_or_worsened[0]
        return (
            f"This PR introduces or worsens reachable risk: `{top.entrypoint}` -> "
            f"`{top.sink}` ({top.risk_label} {top.risk_score}/100)."
        )
    if review.attack_path_count:
        return (
            "Changed code is connected to potential attack paths. "
            "Review the route, guard, validation, and sink chain before merging."
        )
    if review.changed_sink_edges and review.changed_entrypoints:
        return (
            "The diff touches both externally reachable code and sensitive operations, "
            "which is where security review usually pays off most."
        )
    if review.changed_sink_edges:
        return (
            "The diff reaches sensitive operations such as database, file, command, "
            "rendering, or deserialization calls."
        )
    if review.finding_count:
        return (
            "Findings are present in changed files. Confirm whether they are exploitable, "
            "already guarded, or intentionally suppressed."
        )
    return (
        "No immediate security review hotspot was found, but generated artifacts "
        "can still help reviewers inspect the graph context."
    )


def _checklist(review) -> list[str]:
    checks = [
        "- Confirm changed entrypoints require authentication or authorization when needed.",
        "- Check that user-controlled input is validated before reaching sensitive sinks.",
        "- Open `cybergraph-report.html` and inspect any attack paths touching changed files.",
    ]
    if review.finding_count:
        checks.append(
            "- Triage top findings; suppress only accepted risk with "
            "`cybergraph: ignore` or `.cybergraph.toml`."
        )
    if any(delta.status in {"added", "worsened"} for delta in review.risk_deltas):
        checks.append(
            "- Review added or worsened reachable risks before merging; "
            "confirm source, controls, and sink fix."
        )
    return checks
