"""Optional browser checks: pip install playwright; playwright install chromium."""

from pathlib import Path

import pytest

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("width", [390, 1440])
def test_focus_interactions_and_accessibility(tmp_path: Path, width: int):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/run")\ndef run():\n    return eval(request.args["q"])\n'
        '@app.route("/other")\ndef other():\n    return eval(request.args["x"])\n',
        encoding="utf-8",
    )
    build_graph(tmp_path)
    report = generate_html_report(tmp_path, with_source=True)
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000})
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))
        page.goto(report.as_uri())
        page.locator("#cg-focus").check()
        state = page.locator("#cy").evaluate("""el => {
            const cy = el._cyreg.cy;
            return {nodes: cy.nodes('.cg-focus-node').length,
                    visible: cy.nodes().filter(n => n.style('display') !== 'none').length,
                    all: cy.nodes().length};
        }""")
        assert 1 < state["nodes"] == state["visible"] < state["all"]
        assert page.locator("#cg-layout").is_disabled()
        page.set_viewport_size({"width": 390 if width == 1440 else 1440, "height": 1000})
        page.wait_for_timeout(300)
        assert page.locator("#cy").evaluate("""el => {
            const cy = el._cyreg.cy;
            return cy.nodes('.cg-focus-node').every(n => {
                const b = n.renderedBoundingBox({includeLabels: false});
                return b.x1 >= 0 && b.y1 >= 0 && b.x2 <= cy.width() && b.y2 <= cy.height();
            });
        }""")
        page.set_viewport_size({"width": width, "height": 1000})
        page.locator("#cg-motion").check()
        page.wait_for_timeout(180)
        offset = page.locator("#cy").evaluate(
            "el => el._cyreg.cy.edges('.cg-focus-edge').first().style('line-dash-offset')"
        )
        page.wait_for_timeout(180)
        assert offset != page.locator("#cy").evaluate(
            "el => el._cyreg.cy.edges('.cg-focus-edge').first().style('line-dash-offset')"
        )
        page.emulate_media(reduced_motion="reduce")
        page.wait_for_timeout(150)
        assert page.locator("#cg-motion").is_disabled()
        page.locator("#cg-search").fill("no-such-node")
        assert page.locator("#cg-view-counts").inner_text().startswith("0 of")
        page.locator("#cg-search").fill("")
        page.locator("#cy").evaluate(
            "el => el._cyreg.cy.nodes('.cg-focus-node').first().emit('tap')"
        )
        assert "Source:" in page.locator("#cg-details").inner_text()
        page.locator("#cg-theme-toggle").click()
        page.locator("#cg-focus").uncheck()
        assert not page.locator("#cg-layout").is_disabled()
        page.locator("#cg-focus").check()
        page.locator("#cg-mode").select_option("zones")
        assert not page.locator("#cg-focus").is_checked()
        assert page.locator("#cg-motion").is_disabled()
        page.locator("#cg-reset").click()
        assert not page.locator("#cg-focus").is_checked()
        assert page.locator("#cg-focus").is_disabled()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert not errors
        browser.close()


def test_empty_report_has_no_focus_controls_enabled(tmp_path: Path):
    build_graph(tmp_path)
    report = generate_html_report(tmp_path)
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(report.as_uri())
        assert page.locator("#cg-focus").is_disabled()
        assert page.locator("#cg-motion").is_disabled()
        assert "0 of 0 nodes" in page.locator("#cg-view-counts").inner_text()
        browser.close()
