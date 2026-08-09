from pathlib import Path

from cybergraph.cli import main
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def x(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_print_media_block_present_and_overrides_dark(tmp_path):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    text = generate_html_report(repo).read_text(encoding="utf-8")
    idx = text.find("@media print")
    assert idx != -1
    block = text[idx:text.find("</style>", idx)]
    # Both chrome selectors must be hidden in print; the `or` let either one
    # go missing silently.
    assert "#cg-nav" in block
    assert "#cg-theme-toggle" in block
    assert "display: none" in block
    # Must override the persisted dark theme, not just bare :root:
    assert ':root[data-theme="dark"]' in block


def test_print_expands_collapsed_finding_groups(tmp_path):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    text = generate_html_report(repo).read_text(encoding="utf-8")
    assert "beforeprint" in text and "afterprint" in text
    assert "data-finding-group" in text
    # the dead empty no-op rule must be gone
    assert "details[data-finding-group] { }" not in text
