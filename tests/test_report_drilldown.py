# tests/test_report_drilldown.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def h(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_default_off_embeds_no_snippet(tmp_path: Path):
    repo = _repo(tmp_path)
    out = generate_html_report(repo, tmp_path / "r.html")
    html = out.read_text(encoding="utf-8")
    assert '"snippet"' not in html


def test_with_source_embeds_snippet_and_render_code(tmp_path: Path):
    repo = _repo(tmp_path)
    out = generate_html_report(repo, tmp_path / "r.html", with_source=True)
    html = out.read_text(encoding="utf-8")
    assert '"snippet"' in html                 # snippet data embedded
    assert "db.execute" in html                # the finding line is present
    assert "cg-snippet" in html                # details-panel renderer markup/class
