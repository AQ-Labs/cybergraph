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
    assert "#cg-nav" in block or "#cg-theme-toggle" in block
    assert "display: none" in block
    # Must override the persisted dark theme, not just bare :root:
    assert ':root[data-theme="dark"]' in block
