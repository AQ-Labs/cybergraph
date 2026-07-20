from cybergraph.report_sections import about_section
from cybergraph.visualize import _read_asset


def test_about_shows_version_and_repo():
    out = about_section("/x/repo", "1.2.3", truncated=False)
    assert "1.2.3" in out and "/x/repo" in out and 'id="about"' in out


def test_about_truncation_note():
    assert "truncat" in about_section("/x", "1.0", truncated=True).lower()


def test_template_has_nav_and_anchors():
    tpl = _read_asset("report/template.html")
    assert "cg-nav" in tpl
    for anchor in ("#posture", "#explorer", "#findings", "#deps", "#about"):
        assert anchor in tpl
