from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def test_generate_html_report_writes_security_sections(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/users')\n"
        "def users():\n"
        "    return db.execute('select 1')\n",
        encoding="utf-8",
    )
    build_graph(repo)

    output = generate_html_report(repo, tmp_path / "report.html")

    html = output.read_text(encoding="utf-8")
    assert "CyberGraph Security Report" in html
    assert "Security Layers" in html
    assert "Findings" in html
    assert "data-filter='findings-search'" in html
    assert "data-finding-row" in html
    assert "Potential Attack Paths" in html


def test_report_embeds_offline_interactive_explorer(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/users')\n"
        "def users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)

    output = generate_html_report(repo, tmp_path / "report.html")
    html = output.read_text(encoding="utf-8")

    # Explorer scaffolding is present.
    assert "Interactive Graph Explorer" in html
    assert 'id="cy"' in html
    assert "Click a node to inspect" in html
    # Cytoscape is inlined (offline): the library and the graph data both live in the file.
    assert "cytoscape" in html.lower()
    assert "window.CYBERGRAPH" in html
    # No remote script/style references — the report must work with no network.
    assert "<script src=" not in html.replace(" ", "")
    assert "src=\"http" not in html and "src='http" not in html
    assert "<linkhref=\"http" not in html.replace(" ", "")
