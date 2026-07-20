import re
from pathlib import Path

from cybergraph.cli import main
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    # Generate >100 vulnerable routes so findings exceed the report's LIMIT 100
    # cap, exercising the truncation footer that points users at `cybergraph sarif`.
    lines = []
    for i in range(150):
        lines.append(f"@app.route('/users{i}')")
        lines.append(f"def list_users_{i}(request):")
        lines.append("    return db.execute('select ' + request.query['q'])")
        lines.append("")
    (repo / "app.py").write_text("\n".join(lines), encoding="utf-8")
    return repo


def test_all_sections_present_and_self_contained(tmp_path):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    out = generate_html_report(repo, with_source=True)
    text = out.read_text(encoding="utf-8")
    for anchor in ('id="posture"', 'id="explorer"', 'id="findings"', 'id="deps"', 'id="about"'):
        assert anchor in text
    assert "cybergraph sarif" in text
    # No unresolved template tokens (e.g. __FINDINGS_TABLE__); require a leading
    # letter so runs of bare underscores (found in vendored minified JS) don't
    # false-positive.
    assert not re.search(r"__[A-Z][A-Z0-9_]*__", text)
    assert "<link" not in text.lower() and 'src="http' not in text.lower()
    assert "src='http" not in text.lower()
    assert 'href="http' not in text.lower()
    assert "href='http" not in text.lower()
    assert "@import" not in text.lower()
