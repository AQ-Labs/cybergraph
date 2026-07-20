"""Pure render helpers for HTML report sections.

Each function renders one section of the report as an HTML fragment. They are
kept free of I/O so they can be unit-tested in isolation. ``safe_section``
wraps a renderer call so that a single broken section cannot abort the whole
report.
"""

from __future__ import annotations

import html


def safe_section(fn, *args, **kwargs) -> str:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # never let one section abort the whole report
        return (
            "<div class='card section-error'>"
            f"<p class='muted'>Section unavailable: {html.escape(type(exc).__name__)}.</p></div>"
        )


NODE_GROUPS = [
    ("entrypoint", "Entrypoint", "#2563eb"),
    ("function", "Function", "#64748b"),
    ("guard", "Auth/Authz guard", "#16a34a"),
    ("validator", "Validator", "#0d9488"),
    ("sink", "Sensitive sink", "#dc2626"),
    ("secret", "Secret", "#d97706"),
    ("dataflow", "Data flow", "#0891b2"),
    ("dependency", "Dependency", "#7c3aed"),
    ("vulnerability", "Vulnerability", "#991b1b"),
    ("infrastructure", "Infrastructure", "#475569"),
    ("call", "Call", "#cbd5e1"),
    ("file", "File", "#94a3b8"),
]

EDGE_KINDS = [
    ("EXPOSES_ENTRYPOINT", "#2563eb"),
    ("CALLS", "#cbd5e1"),
    ("GUARDS", "#16a34a"),
    ("SANITIZES", "#0d9488"),
    ("REACHES_SINK", "#dc2626"),
    ("USES_SECRET", "#d97706"),
    ("EXPOSES_SECRET", "#dc2626"),
    ("USES_RESOURCE", "#475569"),
    ("AFFECTS_DEPENDENCY", "#7c3aed"),
]


def truncation_banner(graph_data: dict) -> str:
    if not graph_data.get("truncated"):
        return ""
    shown = len(graph_data.get("nodes", []))
    total = int(graph_data.get("counts", {}).get("nodes", shown))
    return (
        "<div style='margin:0 0 12px;padding:10px 12px;border-radius:8px;"
        "background:#fef3c7;color:#92400e;border:1px solid #fde68a;font-size:13px;'>"
        f"Showing {shown} of {total} nodes — raise <code>--max-nodes</code> to see the full graph."
        "</div>"
    )


def legend() -> str:
    items = "".join(
        f"<span class='legend-item'><span class='legend-dot' style='background:{color}'></span>"
        f"{html.escape(label)}</span>"
        for _, label, color in NODE_GROUPS
    )
    return f"<div class='legend'>{items}</div>"


def layers_table(layers) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.label)}</td>"
        f"<td>{item.node_count}</td>"
        f"<td>{item.edge_count}</td>"
        f"<td>{item.finding_count}</td>"
        f"<td>{html.escape(item.description)}</td>"
        "</tr>"
        for item in layers
    )
    return (
        "<table><thead><tr><th>Layer</th><th>Nodes</th><th>Edges</th><th>Findings</th>"
        f"<th>Description</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def findings_table(findings) -> str:
    if not findings:
        return "<p class='muted'>No findings stored yet.</p>"
    rows = "".join(
        "<tr data-finding-row "
        f"data-severity='{html.escape(row['severity'])}' "
        f"data-search='{html.escape(finding_search_text(row))}'>"
        f"<td><span class='pill'>{html.escape(row['severity'])}</span></td>"
        f"<td>{html.escape(row['rule_id'])}</td>"
        f"<td>{html.escape(row['message'])}</td>"
        f"<td><code>{html.escape(row['file_path'] or '-')}:{row['line_start']}</code></td>"
        f"<td>{html.escape(row['tool'])}</td>"
        "</tr>"
        for row in findings
    )
    return (
        "<div class='toolbar'>"
        "<select data-filter='findings-severity' aria-label='Filter findings by severity'>"
        "<option value=''>All severities</option>"
        "<option value='critical'>Critical</option>"
        "<option value='high'>High</option>"
        "<option value='medium'>Medium</option>"
        "<option value='low'>Low</option>"
        "<option value='info'>Info</option>"
        "</select>"
        "</div>"
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Location</th>"
        f"<th>Tool</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def finding_search_text(row) -> str:
    parts = [row["severity"], row["rule_id"], row["message"], row["file_path"] or "", row["tool"]]
    return " ".join(str(part).lower() for part in parts)


def vulnerable_dependencies_table(rows) -> str:
    if not rows:
        return "<p class='muted'>No vulnerable dependency links imported yet.</p>"
    rendered = "".join(
        "<tr>"
        f"<td>{html.escape(row['vulnerability'])}</td>"
        f"<td>{html.escape(row['dependency'])}</td>"
        f"<td><code>{html.escape(row['properties'])}</code></td>"
        "</tr>"
        for row in rows
    )
    return (
        "<table><thead><tr><th>Vulnerability</th><th>Dependency</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rendered}</tbody></table>"
    )


def top_risks_table(risks) -> str:
    if not risks:
        return "<p class='muted'>No prioritized risks found yet.</p>"
    rows = "".join(
        "<tr>"
        f"<td><span class='pill'>{html.escape(str(risk['risk_label']))}</span></td>"
        f"<td>{html.escape(str(risk['risk_score']))}/100</td>"
        f"<td>{html.escape(str(risk['category']))}</td>"
        f"<td>{html.escape(str(risk['title']))}</td>"
        f"<td>{html.escape(str(risk['detail']))}</td>"
        "</tr>"
        for risk in risks
    )
    return (
        "<table><thead><tr><th>Risk</th><th>Score</th><th>Category</th><th>Title</th>"
        f"<th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def attack_paths_list(paths) -> str:
    if not paths:
        return "<p class='muted'>No entrypoint-to-sink paths found yet.</p>"
    return "".join(
        f"<div class='path'><strong>{html.escape(path.entrypoint)}</strong> -> "
        f"<strong>{html.escape(path.sink)}</strong><br>"
        f"<code>{html.escape(' -> '.join(path.nodes))}</code></div>"
        for path in paths
    )
