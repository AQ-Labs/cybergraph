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


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def findings_table(findings, total_findings: int) -> str:
    if not findings:
        return "<p class='muted'>No findings stored yet.</p>"
    rows = "".join(
        "<tr data-finding-row "
        f"data-severity='{html.escape(row['severity'])}' "
        f"data-sev-rank='{_SEV_RANK.get((row['severity'] or '').lower(), 0)}' "
        f"data-search='{html.escape(finding_search_text(row))}' "
        f"style='border-left:4px solid var(--sev-{html.escape((row['severity'] or 'info').lower())})'>"
        f"<td><span class='pill pill--{html.escape((row['severity'] or 'info').lower())}'>{html.escape(row['severity'])}</span></td>"
        f"<td>{html.escape(row['rule_id'])}</td>"
        f"<td>{html.escape(row['message'])}</td>"
        f"<td><code>{html.escape(row['file_path'] or '-')}:{row['line_start']}</code></td>"
        f"<td>{html.escape(row['tool'])}</td>"
        "</tr>"
        for row in findings
    )
    shown = len(findings)
    if total_findings > shown:
        footer = (
            f"<p class='muted'>Showing the top {shown} findings by severity "
            f"({total_findings} total) — run <code>cybergraph sarif</code> or "
            f"<code>cybergraph export-json</code> for the complete set.</p>"
        )
    else:
        footer = f"<p class='muted'>Showing all {total_findings} findings.</p>"
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
        "<table id='findings-table'><thead><tr>"
        "<th data-sort='rank'>Severity</th><th data-sort='text'>Rule</th>"
        "<th data-sort='text'>Message</th><th data-sort='text'>Location</th>"
        "<th data-sort='text'>Tool</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>{footer}"
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


_GRADE_BANDS = [(90, "F"), (85, "E"), (70, "D"), (55, "C"), (40, "B")]
_GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "E": "#dc2626", "F": "#991b1b"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def grade(top_risks: list[dict]) -> tuple[str, str]:
    scores = [int(r.get("risk_score") or 0) for r in top_risks]
    top = max(scores) if scores else 0
    letter = "A"
    for threshold, band in _GRADE_BANDS:
        if top >= threshold:
            letter = band
            break
    if not scores or top < 40:
        return "A", "No significant risks detected."
    return letter, f"Highest risk scored {top}/100 — review the top risks below."


def severity_bar(counts_by_sev: dict[str, int]) -> str:
    total = sum(int(counts_by_sev.get(s, 0)) for s in _SEV_ORDER)
    if total == 0:
        return "<div class='sevbar'><div class='sevbar-seg' style='width:100%;background:var(--sev-info)'>No findings</div></div>"
    segs = []
    for sev in _SEV_ORDER:
        n = int(counts_by_sev.get(sev, 0))
        if n == 0:
            continue
        pct = round(100 * n / total, 2)
        segs.append(
            f"<div class='sevbar-seg' title='{html.escape(sev)}: {n}' "
            f"style='width:{pct}%;background:var(--sev-{sev})'>{n}</div>"
        )
    return f"<div class='sevbar'>{''.join(segs)}</div>"


def delta_strip(delta, prev_ts: str | None) -> str:
    if delta is None or getattr(delta, "is_first", True):
        return ""
    when = (prev_ts or "")[:19]  # trim to seconds for display
    since = f" since scan on {html.escape(when)}" if when else ""
    return (
        "<div class='delta-strip'>"
        f"Since{since}: <strong>{len(delta.new)} new</strong> · "
        f"<strong>{len(delta.regressed)} regressed</strong> · "
        f"<strong>{len(delta.fixed)} fixed</strong> · "
        f"<strong>{len(delta.persisting)} persisting</strong>"
        "</div>"
    )


def posture_section(repo, counts, top_risks, counts_by_sev, delta_html: str) -> str:
    letter, verdict = grade(top_risks)
    color = _GRADE_COLOR[letter]
    chips = "".join(
        f"<div class='chip'><span class='muted'>{label}</span><strong style='display:block;font-size:26px'>{counts.get(key, 0)}</strong></div>"
        for label, key in (("Nodes", "nodes"), ("Edges", "edges"), ("Findings", "findings"),
                            ("Attack Paths", "attack_paths"))
    )
    cards = []
    for r in top_risks[:3]:
        sev = str(r.get("risk_label") or "info").lower()
        cards.append(
            "<div class='card' style='margin:0'>"
            f"<span class='pill pill--{html.escape(sev)}'>{html.escape(str(r.get('risk_score')))}/100</span> "
            f"<strong>{html.escape(str(r.get('title')))}</strong>"
            f"<div class='muted'>{html.escape(str(r.get('category')))} — {html.escape(str(r.get('detail')))}</div>"
            "<a href='#explorer'>jump to path →</a></div>"
        )
    top3 = "".join(cards) or "<p class='muted'>No prioritized risks found yet.</p>"
    return (
        "<section id=\"posture\" class='section card'>"
        "<h2>Security Posture</h2>"
        "<div style='display:flex;gap:var(--space-5);flex-wrap:wrap;align-items:center'>"
        f"<div class='badge-grade' style='background:{color}'>{letter}</div>"
        f"<div style='flex:1;min-width:240px'><p><strong>{html.escape(verdict)}</strong></p>{severity_bar(counts_by_sev)}</div>"
        "</div>"
        f"{delta_html}"
        f"<div class='grid' style='margin-top:var(--space-4)'>{chips}</div>"
        f"<h3>Top risks</h3><div class='grid'>{top3}</div>"
        "</section>"
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
