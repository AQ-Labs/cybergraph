from cybergraph.visualize import _read_asset


def test_print_media_block_hides_chrome():
    css = _read_asset("report/report.css")
    idx = css.find("@media print")
    assert idx != -1
    block = css[idx:]
    assert "#cg-nav" in block and "display: none" in block
    assert ".toolbar" in block


def test_print_block_overrides_dark_theme():
    css = _read_asset("report/report.css")
    idx = css.find("@media print")
    assert idx != -1
    block = css[idx:]
    assert ':root[data-theme="dark"]' in block
