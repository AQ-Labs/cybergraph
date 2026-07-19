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
    return output.read_text(encoding="utf-8")


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
    assert "Attack Surface → Guards" in html or "Attack Surface \u2192 Guards" in html
