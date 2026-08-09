"""Phase 1 visual-identity regressions: theme variables and neon graph styling."""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _report_html(tmp_path: Path) -> str:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import sqlite3\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def get_items(q: str):\n"
        "    db = sqlite3.connect('x.db')\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    output = tmp_path / "report.html"
    generate_html_report(repo, output)
    html = output.read_text(encoding="utf-8")
    # The fixture has a real SQL-injection finding and a real attack path. Pin
    # that the report actually *renders* them, so every identity test below
    # depends on finding-derived content rather than passing on an empty repo:
    # `CG-SQL-EXEC`, the route handler `get_items` and the finding-group markup
    # are all absent when there is nothing to report (measured), unlike the
    # static CSS/JS scaffolding the tokens used to rest on.
    assert "CG-SQL-EXEC" in html, "fixture must render its real finding"
    assert "get_items" in html, "fixture must render its real entrypoint"
    return html


def _style_block(html: str) -> str:
    return html[html.index("<style>") : html.index("</style>")]


def test_component_css_has_no_hardcoded_light_backgrounds(tmp_path: Path) -> None:
    css = _style_block(_report_html(tmp_path))
    offenders = [
        line.strip()
        for line in css.splitlines()
        if re.search(r"background:\s*(white|#fff\b|#ffffff)", line)
    ]
    assert offenders == []


def test_theme_variables_cover_inputs_pills_and_warnings(tmp_path: Path) -> None:
    css = _style_block(_report_html(tmp_path))
    for token in ("--input-bg", "--pill-bg", "--accent", "--warn-bg", "--code"):
        assert f"{token}:" in css, f"missing theme variable {token}"
    # Components consume the variables rather than fixed colors.
    for usage in ("var(--input-bg)", "var(--pill-bg)", "var(--muted)", "var(--code)"):
        assert usage in css


def test_graph_styles_are_theme_driven(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "THEMES = {" in html
    assert "activeTheme()" in html
    # Neon glow underlays and severity-scaled sizes.
    assert "underlay-opacity" in html
    assert "SEV_SIZE" in html
    # The graph restyles when the theme toggle flips.
    assert "MutationObserver" in html and "data-theme" in html


def test_dark_palette_brightens_nodes_and_dims_edges(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "#38bdf8" in html  # neon entrypoint
    assert "#f87171" in html  # neon sink
    assert "rgba(148, 163, 184, 0.35)" in html  # dimmed base edges


def test_explainer_cards_replace_dot_legend(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "class='explainer'" in html
    for word in ("NODE", "EDGE", "ZONE"):
        assert word in html
    assert "Attack Surface" in html and "Sensitive Sinks" in html


def test_guided_first_view_highlights_top_risk(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "highlightPath('0')" in html
    assert "pathNarrative" in html
    assert "Start here: the #1 risk" in html
    # The guided view must reference the *real* top risk, not just the static
    # scaffolding: the #1 risk here is the SQL sink reached from the route.
    assert "app.py::get_items -&gt; db.execute" in html


def test_plain_language_labels_prefer_routes(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "displayLabel" in html
    assert "props.route" in html


def test_howto_intro_present(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "How to read this report" in html
    assert '<details class="howto">' in html


def test_exported_nodes_carry_security_zones(tmp_path: Path) -> None:
    from cybergraph.graph_export import build_graph_data

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import sqlite3\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def get_items(q: str):\n"
        "    db = sqlite3.connect('x.db')\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    data = build_graph_data(repo)
    zones = {node.get("zone") for node in data["nodes"]}
    assert None not in zones
    assert "attack-surface" in zones
    assert "sinks" in zones


def test_zones_view_present_in_report(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "View: security zones" in html
    assert "buildZoneElements" in html
    assert "'zone:' + zone" in html  # compound parents
    # Both operands parse to the identical string (`→` and the escape
    # spelling are one glyph), so the `or` was a no-op. One assertion, once.
    assert "Attack Surface → Guards" in html
    # ...and the exported graph really carries the zones the view renders.
    from cybergraph.graph_export import build_graph_data

    repo = tmp_path / "repo"
    zones = {node.get("zone") for node in build_graph_data(repo)["nodes"]}
    assert "attack-surface" in zones and "sinks" in zones, zones


def test_findings_grouped_by_rule(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "data-finding-group" in html
    assert "class='finding-group" in html
    assert "data-finding-row" in html  # rows survive inside groups
    assert "fg-count" in html
    # The group markup (not just the CSS class) must name the real rule and its
    # count. Measured absent on an empty repo, unlike the scaffolding above.
    assert "<strong>CG-SQL-EXEC</strong>" in html
    assert "1 finding" in html


def test_top_risks_render_as_clickable_cards(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "data-risk-jump" in html
    assert "cg-risk-strip" not in html  # duplicated JS strip removed
    # A rendered card must carry the real risk title, not just the JS hook.
    assert "data-title='app.py::get_items -&gt; db.execute'" in html


def test_stat_tiles_show_severity_accents(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "stat-crit" in html or "stat-high" in html
    # `stat-crit`/`stat-high` are static <style> rules; the load-bearing check
    # is that a tile shows the real severity count for the fixture's finding.
    assert "<span class='stat-high'>1 high</span>" in html


def test_motion_is_present_and_reduced_motion_safe(tmp_path: Path) -> None:
    html = _report_html(tmp_path)
    assert "@keyframes cg-fade" in html
    assert "prefers-reduced-motion" in html
    assert "function pulse(" in html
