"""HTML visualization report generation."""

from __future__ import annotations

import html
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.layers import summarize_layers


def generate_html_report(repo_root: Path, output: Path | None = None) -> Path:
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
    output.write_text(
        _render_html(repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths),
        encoding="utf-8",
    )
    return output


def _render_html(repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CyberGraph Report</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif; }}
    body {{ margin: 0; background: #f7f8fa; color: #161b22; }}
    header {{ background: #0b1220; color: white; padding: 28px 36px; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 28px 24px 48px; }}
    h1 {{ margin: 0 0 8px; font-size: 30px; }}
    h2 {{ margin: 28px 0 12px; font-size: 18px; }}
    .muted {{ color: #667085; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .stat, table {{ background: white; border: 1px solid #d0d7de; border-radius: 8px; }}
    .stat {{ padding: 16px; }}
    .stat strong {{ display: block; font-size: 26px; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #d0d7de; text-align: left; vertical-align: top; }}
    th {{ background: #f0f3f6; font-size: 13px; }}
    tr:last-child td {{ border-bottom: 0; }}
    .pill {{ display: inline-block; padding: 3px 8px; border-radius: 999px; background: #eef6ff; color: #075985; font-size: 12px; }}
    .path {{ background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px; margin-bottom: 10px; }}
    code {{ color: #7c2d12; }}
  </style>
</head>
<body>
  <header>
    <h1>CyberGraph Security Report</h1>
    <div>{html.escape(str(repo_root))}</div>
  </header>
  <main>
    <section class="grid">
      <div class="stat"><span class="muted">Nodes</span><strong>{counts["nodes"]}</strong></div>
      <div class="stat"><span class="muted">Edges</span><strong>{counts["edges"]}</strong></div>
      <div class="stat"><span class="muted">Findings</span><strong>{counts["findings"]}</strong></div>
      <div class="stat"><span class="muted">Attack Paths</span><strong>{len(attack_paths)}</strong></div>
    </section>
    <h2>Security Layers</h2>
    {_layers_table(layers)}
    <h2>Vulnerable Dependencies</h2>
    {_vulnerable_dependencies_table(vulnerable_dependencies)}
    <h2>Findings</h2>
    {_findings_table(findings)}
    <h2>Potential Attack Paths</h2>
    {_attack_paths(attack_paths)}
  </main>
</body>
</html>
"""


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
    return f"<table><thead><tr><th>Layer</th><th>Nodes</th><th>Edges</th><th>Findings</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table>"


def _findings_table(findings) -> str:
    if not findings:
        return "<p class='muted'>No findings stored yet.</p>"
    rows = "".join(
        "<tr>"
        f"<td><span class='pill'>{html.escape(row['severity'])}</span></td>"
        f"<td>{html.escape(row['rule_id'])}</td>"
        f"<td>{html.escape(row['message'])}</td>"
        f"<td><code>{html.escape(row['file_path'] or '-')}:{row['line_start']}</code></td>"
        f"<td>{html.escape(row['tool'])}</td>"
        "</tr>"
        for row in findings
    )
    return f"<table><thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Location</th><th>Tool</th></tr></thead><tbody>{rows}</tbody></table>"


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
    return f"<table><thead><tr><th>Vulnerability</th><th>Dependency</th><th>Evidence</th></tr></thead><tbody>{rendered}</tbody></table>"


def _attack_paths(paths) -> str:
    if not paths:
        return "<p class='muted'>No entrypoint-to-sink paths found yet.</p>"
    return "".join(
        f"<div class='path'><strong>{html.escape(path.entrypoint)}</strong> -> "
        f"<strong>{html.escape(path.sink)}</strong><br><code>{html.escape(' -> '.join(path.nodes))}</code></div>"
        for path in paths
    )
