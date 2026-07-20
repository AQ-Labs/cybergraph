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
from cybergraph.report_sections import (
    attack_paths_list,
    findings_table,
    layers_table,
    legend,
    top_risks_table,
    truncation_banner,
    vulnerable_dependencies_table,
)
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.layers import summarize_layers

# Backward-compatible aliases for existing imports/tests.
_truncation_banner = truncation_banner
_findings_table = findings_table
_top_risks_table = top_risks_table
_legend = legend


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
        "__TOP_RISKS_TABLE__": top_risks_table(graph_data.get("top_risks", [])),
        "__LAYERS_TABLE__": layers_table(layers),
        "__VULN_DEPS_TABLE__": vulnerable_dependencies_table(vulnerable_dependencies),
        "__FINDINGS_TABLE__": findings_table(findings),
        "__ATTACK_PATHS_LIST__": attack_paths_list(attack_paths),
        "__LEGEND__": legend(),
        "__TRUNCATION_BANNER__": truncation_banner(graph_data),
        "__GRAPH_JSON__": _embed_json(graph_data),
        "__CYTOSCAPE_SRC__": _load_cytoscape_source(),
        "__CSS__": _read_asset("report/report.css"),
        "__REPORT_JS__": _read_asset("report/report.js"),
    }
    for token, value in replacements.items():
        template = template.replace(token, value)
    return template

