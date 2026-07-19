# tests/test_report_theme.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    build_graph(repo)
    return repo


def test_report_is_theme_aware(tmp_path: Path):
    html = generate_html_report(_repo(tmp_path), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "--bg" in html and "--fg" in html                 # CSS variables
    assert "prefers-color-scheme: dark" in html               # auto dark
    assert '[data-theme="dark"]' in html                      # explicit override
    assert 'id="cg-theme-toggle"' in html                     # toggle control
    assert "localStorage" in html and "cybergraph-theme" in html  # persistence + anti-FOUC
