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
    about_section,
    attack_paths_list,
    delta_strip,
    findings_table,
    layers_table,
    legend,
    posture_section,
    safe_section,
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
        sev_counts = {
            row["severity"]: row["n"]
            for row in store.conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            )
        }
    finally:
        store.close()

    delta_html = gather_delta_html(repo_root)

    layers = summarize_layers(repo_root)
    attack_paths = find_attack_paths(repo_root, limit=25)
    graph_data = build_graph_data(repo_root)
    if with_source:
        from cybergraph.report_source import attach_source_snippets

        attach_source_snippets(repo_root, graph_data)
    output.write_text(
        _render_html(
            repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data,
            sev_counts, delta_html,
        ),
        encoding="utf-8",
    )
    return output


def gather_delta_html(repo_root: Path) -> str:
    try:
        from cybergraph import history

        delta = history.scan_delta(repo_root)
        scans = history.list_scans(repo_root, limit=2)
        prev_ts = scans[1]["ts"] if len(scans) > 1 else None
        return delta_strip(delta, prev_ts)
    except Exception:
        return ""


def _read_asset(rel: str) -> str:
    return (files("cybergraph") / "assets" / rel).read_text(encoding="utf-8")


def _load_cytoscape_source() -> str:
    return _read_asset("cytoscape.min.js")


def _embed_json(data) -> str:
    # Inline JSON safely inside a <script> tag.
    return json.dumps(data).replace("</", "<\\/")


def _cybergraph_version() -> str:
    try:
        from importlib.metadata import version

        return version("cybergraph")
    except Exception:
        return "unknown"


def _render_html(
    repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data,
    sev_counts, delta_html,
) -> str:
    template = _read_asset("report/template.html")
    replacements = {
        "__REPO__": html.escape(str(repo_root)),
        "__POSTURE__": safe_section(
            posture_section,
            {**counts, "attack_paths": len(attack_paths)},
            graph_data.get("top_risks", []),
            sev_counts,
            delta_html,
        ),
        "__LAYERS_TABLE__": layers_table(layers),
        "__VULN_DEPS_TABLE__": vulnerable_dependencies_table(vulnerable_dependencies),
        "__FINDINGS_TABLE__": findings_table(findings, counts.get("findings", len(findings))),
        "__ATTACK_PATHS_LIST__": attack_paths_list(attack_paths),
        "__LEGEND__": legend(),
        "__TRUNCATION_BANNER__": truncation_banner(graph_data),
        "__ABOUT__": safe_section(
            about_section, str(repo_root), _cybergraph_version(),
            bool(graph_data.get("truncated")),
        ),
        "__GRAPH_JSON__": _embed_json(graph_data),
        "__CYTOSCAPE_SRC__": _load_cytoscape_source(),
        "__CSS__": _read_asset("report/report.css"),
        "__REPORT_JS__": _read_asset("report/report.js"),
    }
    for token, value in replacements.items():
        template = template.replace(token, value)
    return template

