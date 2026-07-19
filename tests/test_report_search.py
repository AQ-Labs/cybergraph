# tests/test_report_search.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_single_unified_search_box(tmp_path: Path):
    html = generate_html_report(_repo(tmp_path), tmp_path / "r.html").read_text(encoding="utf-8")
    # the findings table no longer has its own text search input
    assert (
        "data-filter='findings-search'" not in html
        and 'data-filter="findings-search"' not in html
    )
    # exactly one search input remains: the shared #cg-search
    assert html.count('type="search"') + html.count("type='search'") == 1
    # the findings filter is wired to the shared box
    assert "getElementById('cg-search')" in html
    # the findings severity filter is preserved (kept separate by design)
    assert "findings-severity" in html
