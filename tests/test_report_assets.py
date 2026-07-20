from pathlib import Path

from cybergraph.visualize import _read_asset, generate_html_report


def test_read_asset_loads_css_and_js():
    css = _read_asset("report/report.css")
    js = _read_asset("report/report.js")
    assert ":root" in css and "cytoscape" in js.lower()


def _tiny_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def x(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_report_is_self_contained_single_file(tmp_path):
    from cybergraph.cli import main
    repo = _tiny_repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    out = generate_html_report(repo)
    text = out.read_text(encoding="utf-8")
    # No external asset references — everything inlined.
    assert "<link" not in text.lower()
    assert 'src="http' not in text.lower()
    assert "url(http" not in text.lower()
    # Skeleton tokens all resolved.
    assert "__CSS__" not in text and "__REPORT_JS__" not in text and "__GRAPH_JSON__" not in text
