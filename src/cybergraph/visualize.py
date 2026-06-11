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
    graph_data = build_graph_data(repo_root)
    output.write_text(
        _render_html(
            repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data
        ),
        encoding="utf-8",
    )
    return output


def _load_cytoscape_source() -> str:
    return (files("cybergraph") / "assets" / "cytoscape.min.js").read_text(encoding="utf-8")


def _embed_json(data) -> str:
    # Inline JSON safely inside a <script> tag.
    return json.dumps(data).replace("</", "<\\/")


def _render_html(
    repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data
) -> str:
    template = _HTML_TEMPLATE
    replacements = {
        "__REPO__": html.escape(str(repo_root)),
        "__NODES__": str(counts["nodes"]),
        "__EDGES__": str(counts["edges"]),
        "__FINDINGS__": str(counts["findings"]),
        "__ATTACK_PATHS__": str(len(attack_paths)),
        "__LAYERS_TABLE__": _layers_table(layers),
        "__VULN_DEPS_TABLE__": _vulnerable_dependencies_table(vulnerable_dependencies),
        "__FINDINGS_TABLE__": _findings_table(findings),
        "__ATTACK_PATHS_LIST__": _attack_paths(attack_paths),
        "__LEGEND__": _legend(),
        "__GRAPH_JSON__": _embed_json(graph_data),
        "__CYTOSCAPE_SRC__": _load_cytoscape_source(),
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
    ("dependency", "Dependency", "#7c3aed"),
    ("vulnerability", "Vulnerability", "#991b1b"),
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
    ("AFFECTS_DEPENDENCY", "#7c3aed"),
]


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
        "<input data-filter='findings-search' type='search' "
        "placeholder='Search findings by rule, file, message, or tool'>"
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


def _attack_paths(paths) -> str:
    if not paths:
        return "<p class='muted'>No entrypoint-to-sink paths found yet.</p>"
    return "".join(
        f"<div class='path'><strong>{html.escape(path.entrypoint)}</strong> -> "
        f"<strong>{html.escape(path.sink)}</strong><br>"
        f"<code>{html.escape(' -> '.join(path.nodes))}</code></div>"
        for path in paths
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CyberGraph Report</title>
  <style>
    :root { color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif; }
    body { margin: 0; background: #f7f8fa; color: #161b22; }
    header { background: #0b1220; color: white; padding: 28px 36px; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px 24px 48px; }
    h1 { margin: 0 0 8px; font-size: 30px; }
    h2 { margin: 28px 0 12px; font-size: 18px; }
    .muted { color: #667085; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
    .stat, table { background: white; border: 1px solid #d0d7de; border-radius: 8px; }
    .stat { padding: 16px; }
    .stat strong { display: block; font-size: 26px; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #d0d7de; text-align: left; vertical-align: top; }
    th { background: #f0f3f6; font-size: 13px; }
    tr:last-child td { border-bottom: 0; }
    .pill { display: inline-block; padding: 3px 8px; border-radius: 999px; background: #eef6ff; color: #075985; font-size: 12px; }
    .path { background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px; margin-bottom: 10px; }
    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin: 0 0 12px; align-items: center; }
    .toolbar input, .toolbar select, .toolbar button { border: 1px solid #b6c2cf; border-radius: 6px; padding: 9px 10px; background: white; color: #161b22; font-size: 13px; }
    .toolbar input { min-width: min(360px, 100%); flex: 1; }
    .toolbar button { cursor: pointer; }
    .toolbar button:hover { background: #eef2f7; }
    code { color: #7c2d12; }
    .explorer { display: grid; grid-template-columns: 1fr 300px; gap: 12px; }
    #cy { height: 540px; background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; }
    .details { background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 14px; height: 540px; overflow: auto; font-size: 13px; }
    .details h3 { margin: 0 0 8px; font-size: 15px; }
    .details .kv { margin: 4px 0; }
    .details .tag { display: inline-block; padding: 2px 7px; border-radius: 999px; font-size: 11px; color: white; }
    .legend { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0 14px; font-size: 12px; color: #475467; }
    .legend-item { display: inline-flex; align-items: center; gap: 6px; }
    .legend-dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
    @media (max-width: 820px) { .explorer { grid-template-columns: 1fr; } .details { height: auto; } }
  </style>
</head>
<body>
  <header>
    <h1>CyberGraph Security Report</h1>
    <div>__REPO__</div>
  </header>
  <main>
    <section class="grid">
      <div class="stat"><span class="muted">Nodes</span><strong>__NODES__</strong></div>
      <div class="stat"><span class="muted">Edges</span><strong>__EDGES__</strong></div>
      <div class="stat"><span class="muted">Findings</span><strong>__FINDINGS__</strong></div>
      <div class="stat"><span class="muted">Attack Paths</span><strong>__ATTACK_PATHS__</strong></div>
    </section>

    <h2>Interactive Graph Explorer</h2>
    <div class="toolbar">
      <input id="cg-search" type="search" placeholder="Search nodes by name, file, or group">
      <select id="cg-layer" aria-label="Filter by security layer">
        <option value="">All layers</option>
      </select>
      <select id="cg-severity" aria-label="Filter by minimum severity">
        <option value="">Any severity</option>
        <option value="critical">Critical</option>
        <option value="high">High+</option>
        <option value="medium">Medium+</option>
        <option value="low">Low+</option>
      </select>
      <select id="cg-path" aria-label="Highlight an attack path">
        <option value="">Highlight attack path…</option>
      </select>
      <select id="cg-layout" aria-label="Graph layout">
        <option value="breadthfirst">Layout: hierarchy</option>
        <option value="cose">Layout: force</option>
        <option value="circle">Layout: circle</option>
        <option value="grid">Layout: grid</option>
      </select>
      <button id="cg-zoom-in" type="button">+</button>
      <button id="cg-zoom-out" type="button">−</button>
      <button id="cg-reset" type="button">Reset</button>
    </div>
    __LEGEND__
    <div class="explorer">
      <div id="cy"></div>
      <div class="details" id="cg-details"><p class="muted">Click a node to inspect its security evidence.</p></div>
    </div>

    <h2>Security Layers</h2>
    __LAYERS_TABLE__
    <h2>Vulnerable Dependencies</h2>
    __VULN_DEPS_TABLE__
    <h2>Findings</h2>
    __FINDINGS_TABLE__
    <h2>Potential Attack Paths</h2>
    __ATTACK_PATHS_LIST__
  </main>

  <script>__CYTOSCAPE_SRC__</script>
  <script>window.CYBERGRAPH = __GRAPH_JSON__;</script>
  <script>
    (function () {
      const data = window.CYBERGRAPH || { nodes: [], edges: [], attack_paths: [] };
      const GROUP_COLORS = {
        entrypoint: '#2563eb', function: '#64748b', guard: '#16a34a', validator: '#0d9488',
        sink: '#dc2626', secret: '#d97706', dependency: '#7c3aed', vulnerability: '#991b1b',
        call: '#cbd5e1', file: '#94a3b8'
      };
      const EDGE_COLORS = {
        EXPOSES_ENTRYPOINT: '#2563eb', CALLS: '#cbd5e1', GUARDS: '#16a34a', SANITIZES: '#0d9488',
        REACHES_SINK: '#dc2626', USES_SECRET: '#d97706', AFFECTS_DEPENDENCY: '#7c3aed'
      };
      const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, '': -1 };

      if (typeof cytoscape === 'undefined' || !document.getElementById('cy')) return;

      const elements = [];
      data.nodes.forEach(function (n) {
        elements.push({ data: Object.assign({}, n) });
      });
      data.edges.forEach(function (e) {
        elements.push({ data: { id: e.id, source: e.source, target: e.target, kind: e.kind, label: e.kind } });
      });

      const cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        wheelSensitivity: 0.2,
        style: [
          { selector: 'node', style: {
            'background-color': function (ele) { return GROUP_COLORS[ele.data('group')] || '#94a3b8'; },
            'label': 'data(label)', 'font-size': 9, 'color': '#0b1220', 'text-wrap': 'ellipsis',
            'text-max-width': 90, 'width': 18, 'height': 18, 'border-width': 0
          } },
          { selector: 'node[group = "entrypoint"]', style: { 'width': 24, 'height': 24, 'shape': 'round-rectangle' } },
          { selector: 'node[group = "sink"]', style: { 'shape': 'triangle', 'width': 22, 'height': 22 } },
          { selector: 'node[group = "vulnerability"]', style: { 'shape': 'diamond' } },
          { selector: 'node[severity = "critical"], node[severity = "high"]', style: { 'border-width': 3, 'border-color': '#dc2626' } },
          { selector: 'node[severity = "medium"]', style: { 'border-width': 2, 'border-color': '#d97706' } },
          { selector: 'edge', style: {
            'width': 1.4, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
            'line-color': function (ele) { return EDGE_COLORS[ele.data('kind')] || '#cbd5e1'; },
            'target-arrow-color': function (ele) { return EDGE_COLORS[ele.data('kind')] || '#cbd5e1'; },
            'arrow-scale': 0.8
          } },
          { selector: 'edge[kind = "REACHES_SINK"]', style: { 'width': 2.4 } },
          { selector: '.cg-dim', style: { 'opacity': 0.12 } },
          { selector: '.cg-hl', style: { 'opacity': 1, 'border-width': 4, 'border-color': '#f59e0b', 'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b', 'z-index': 99 } }
        ],
        layout: { name: 'breadthfirst', directed: true, padding: 12, spacingFactor: 1.1 }
      });

      // Populate the layer filter from the groups actually present.
      const layerSelect = document.getElementById('cg-layer');
      const present = Array.from(new Set(data.nodes.map(function (n) { return n.group; }))).sort();
      present.forEach(function (g) {
        const opt = document.createElement('option');
        opt.value = g; opt.textContent = g.charAt(0).toUpperCase() + g.slice(1);
        layerSelect.appendChild(opt);
      });

      // Populate the attack-path selector.
      const pathSelect = document.getElementById('cg-path');
      (data.attack_paths || []).forEach(function (p, i) {
        const opt = document.createElement('option');
        opt.value = String(i);
        opt.textContent = (p.entrypoint || '?') + ' → ' + (p.sink || '?');
        pathSelect.appendChild(opt);
      });

      function applyFilters() {
        const q = (document.getElementById('cg-search').value || '').toLowerCase();
        const layer = document.getElementById('cg-layer').value;
        const minSev = SEV_RANK[document.getElementById('cg-severity').value] ?? -1;
        cy.batch(function () {
          cy.nodes().forEach(function (n) {
            const hay = (n.data('label') + ' ' + (n.data('file') || '') + ' ' + n.data('group')).toLowerCase();
            const matchText = !q || hay.indexOf(q) !== -1;
            const matchLayer = !layer || n.data('group') === layer;
            const matchSev = (SEV_RANK[n.data('severity')] ?? -1) >= minSev;
            n.style('display', (matchText && matchLayer && matchSev) ? 'element' : 'none');
          });
          cy.edges().forEach(function (e) {
            const vis = e.source().style('display') !== 'none' && e.target().style('display') !== 'none';
            e.style('display', vis ? 'element' : 'none');
          });
        });
      }

      function highlightPath(idx) {
        cy.elements().removeClass('cg-hl cg-dim');
        if (idx === '' || idx === null) return;
        const p = (data.attack_paths || [])[Number(idx)];
        if (!p) return;
        const ids = p.nodes || [];
        const inPath = cy.collection();
        ids.forEach(function (id) { inPath.merge(cy.getElementById(id)); });
        for (let i = 0; i < ids.length - 1; i++) {
          inPath.merge(cy.edges('[source = "' + ids[i] + '"][target = "' + ids[i + 1] + '"]'));
        }
        cy.elements().addClass('cg-dim');
        inPath.removeClass('cg-dim').addClass('cg-hl');
        if (inPath.length) cy.animate({ fit: { eles: inPath, padding: 60 }, duration: 350 });
      }

      function esc(s) { return String(s == null ? '' : s).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }); }

      function showDetails(node) {
        const d = node.data();
        const color = GROUP_COLORS[d.group] || '#94a3b8';
        let html = '<h3>' + esc(d.label) + '</h3>';
        html += '<div class="kv"><span class="tag" style="background:' + color + '">' + esc(d.group) + '</span></div>';
        if (d.file) html += '<div class="kv"><strong>Location:</strong> <code>' + esc(d.file) + ':' + esc(d.line) + '</code></div>';
        html += '<div class="kv"><strong>Kind:</strong> ' + esc(d.kind) + '</div>';
        if (d.severity) html += '<div class="kv"><strong>Severity:</strong> ' + esc(d.severity) + '</div>';
        const findings = d.findings || [];
        if (findings.length) {
          html += '<div class="kv"><strong>Findings:</strong><ul>';
          findings.forEach(function (f) { html += '<li>' + esc(f.severity) + ' ' + esc(f.rule_id) + ': ' + esc(f.message) + '</li>'; });
          html += '</ul></div>';
        }
        const props = d.properties || {};
        const keys = Object.keys(props).filter(function (k) { return props[k] && k !== 'decorators'; });
        if (keys.length) {
          html += '<div class="kv"><strong>Properties:</strong><ul>';
          keys.forEach(function (k) { html += '<li>' + esc(k) + ': ' + esc(JSON.stringify(props[k])) + '</li>'; });
          html += '</ul></div>';
        }
        const neighbors = node.neighborhood('node').map(function (n) { return n.data('label'); });
        if (neighbors.length) html += '<div class="kv"><strong>Connected:</strong> ' + esc(neighbors.slice(0, 12).join(', ')) + '</div>';
        document.getElementById('cg-details').innerHTML = html;
      }

      cy.on('tap', 'node', function (evt) {
        cy.elements().removeClass('cg-hl cg-dim');
        const node = evt.target;
        const hood = node.closedNeighborhood();
        cy.elements().addClass('cg-dim');
        hood.removeClass('cg-dim');
        node.removeClass('cg-dim').addClass('cg-hl');
        showDetails(node);
      });
      cy.on('tap', function (evt) { if (evt.target === cy) cy.elements().removeClass('cg-hl cg-dim'); });

      document.getElementById('cg-search').addEventListener('input', applyFilters);
      document.getElementById('cg-layer').addEventListener('change', applyFilters);
      document.getElementById('cg-severity').addEventListener('change', applyFilters);
      document.getElementById('cg-path').addEventListener('change', function (e) { highlightPath(e.target.value); });
      document.getElementById('cg-layout').addEventListener('change', function (e) {
        cy.layout({ name: e.target.value, directed: true, padding: 12, spacingFactor: 1.1, animate: false }).run();
      });
      document.getElementById('cg-zoom-in').addEventListener('click', function () { cy.zoom(cy.zoom() * 1.2); });
      document.getElementById('cg-zoom-out').addEventListener('click', function () { cy.zoom(cy.zoom() / 1.2); });
      document.getElementById('cg-reset').addEventListener('click', function () {
        document.getElementById('cg-search').value = '';
        document.getElementById('cg-layer').value = '';
        document.getElementById('cg-severity').value = '';
        document.getElementById('cg-path').value = '';
        applyFilters();
        cy.elements().removeClass('cg-hl cg-dim');
        cy.fit(undefined, 30);
      });
    })();
  </script>
  <script>
    const findingSearch = document.querySelector('[data-filter="findings-search"]');
    const findingSeverity = document.querySelector('[data-filter="findings-severity"]');
    function filterFindings() {
      const query = (findingSearch?.value || '').toLowerCase();
      const severity = findingSeverity?.value || '';
      document.querySelectorAll('[data-finding-row]').forEach((row) => {
        const matchesText = row.dataset.search.includes(query);
        const matchesSeverity = !severity || row.dataset.severity === severity;
        row.hidden = !(matchesText && matchesSeverity);
      });
    }
    findingSearch?.addEventListener('input', filterFindings);
    findingSeverity?.addEventListener('change', filterFindings);
  </script>
</body>
</html>
"""
