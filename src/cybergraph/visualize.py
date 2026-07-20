"""HTML visualization report generation.

The report is a single self-contained, offline HTML file. It now embeds an
interactive Cytoscape.js graph explorer above the existing static tables, with
node/edge styling, search and filters, a details panel, and entrypoint-to-sink
attack-path highlighting. The Cytoscape library is vendored and inlined so the
report works with no network access.
"""

from __future__ import annotations

import html
import json
from importlib.resources import files
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.graph_export import build_graph_data
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.layers import summarize_layers


def generate_html_report(repo_root: Path, output: Path | None = None, *, with_source: bool = False) -> Path:
    repo_root = repo_root.resolve()
    output = output or repo_root / ".cybergraph" / "report.html"
    output.parent.mkdir(parents=True, exist_ok=True)

    store = GraphStore.open_for_repo(repo_root)
    try:
        counts = store.counts()
        findings = store.conn.execute(
            """
            SELECT rule_id, severity, message, file_path, line_start, tool
            FROM findings
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                file_path,
                line_start
            LIMIT 100
            """
        ).fetchall()
        vulnerable_dependencies = store.conn.execute(
            """
            SELECT v.name AS vulnerability, d.name AS dependency, e.properties AS properties
            FROM edges e
            JOIN nodes v ON v.key = e.source
            JOIN nodes d ON d.key = e.target
            WHERE e.kind = 'AFFECTS_DEPENDENCY'
            ORDER BY v.name, d.name
            LIMIT 100
            """
        ).fetchall()
    finally:
        store.close()

    layers = summarize_layers(repo_root)
    attack_paths = find_attack_paths(repo_root, limit=25)
    graph_data = build_graph_data(repo_root)
    if with_source:
        from cybergraph.report_source import attach_source_snippets

        attach_source_snippets(repo_root, graph_data)
    output.write_text(
        _render_html(
            repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data
        ),
        encoding="utf-8",
    )
    return output


def _read_asset(rel: str) -> str:
    return (files("cybergraph") / "assets" / rel).read_text(encoding="utf-8")


def _load_cytoscape_source() -> str:
    return _read_asset("cytoscape.min.js")


def _embed_json(data) -> str:
    # Inline JSON safely inside a <script> tag.
    return json.dumps(data).replace("</", "<\\/")


def _render_html(
    repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data
) -> str:
    template = _read_asset("report/template.html")
    replacements = {
        "__REPO__": html.escape(str(repo_root)),
        "__NODES__": str(counts["nodes"]),
        "__EDGES__": str(counts["edges"]),
        "__FINDINGS__": str(counts["findings"]),
        "__ATTACK_PATHS__": str(len(attack_paths)),
        "__TOP_RISKS_TABLE__": _top_risks_table(graph_data.get("top_risks", [])),
        "__LAYERS_TABLE__": _layers_table(layers),
        "__VULN_DEPS_TABLE__": _vulnerable_dependencies_table(vulnerable_dependencies),
        "__FINDINGS_TABLE__": _findings_table(findings),
        "__ATTACK_PATHS_LIST__": _attack_paths(attack_paths),
        "__LEGEND__": _legend(),
        "__TRUNCATION_BANNER__": _truncation_banner(graph_data),
        "__GRAPH_JSON__": _embed_json(graph_data),
        "__CYTOSCAPE_SRC__": _load_cytoscape_source(),
        "__CSS__": _read_asset("report/report.css"),
        "__REPORT_JS__": _read_asset("report/report.js"),
    }
    for token, value in replacements.items():
        template = template.replace(token, value)
    return template


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


def _truncation_banner(graph_data: dict) -> str:
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


def _legend() -> str:
    items = "".join(
        f"<span class='legend-item'><span class='legend-dot' style='background:{color}'></span>"
        f"{html.escape(label)}</span>"
        for _, label, color in NODE_GROUPS
    )
    return f"<div class='legend'>{items}</div>"


def _layers_table(layers) -> str:
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


def _findings_table(findings) -> str:
    if not findings:
        return "<p class='muted'>No findings stored yet.</p>"
    rows = "".join(
        "<tr data-finding-row "
        f"data-severity='{html.escape(row['severity'])}' "
        f"data-search='{html.escape(_finding_search_text(row))}'>"
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


def _finding_search_text(row) -> str:
    parts = [row["severity"], row["rule_id"], row["message"], row["file_path"] or "", row["tool"]]
    return " ".join(str(part).lower() for part in parts)


def _vulnerable_dependencies_table(rows) -> str:
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


def _top_risks_table(risks) -> str:
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


def _attack_paths(paths) -> str:
    if not paths:
        return "<p class='muted'>No entrypoint-to-sink paths found yet.</p>"
    return "".join(
        f"<div class='path'><strong>{html.escape(path.entrypoint)}</strong> -> "
        f"<strong>{html.escape(path.sink)}</strong><br>"
        f"<code>{html.escape(' -> '.join(path.nodes))}</code></div>"
        for path in paths
    )

