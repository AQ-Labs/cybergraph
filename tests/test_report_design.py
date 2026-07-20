from cybergraph.visualize import _read_asset


def test_css_defines_severity_palette_tokens():
    css = _read_asset("report/report.css")
    for token in ("--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-info"):
        assert token in css
    for hexval in ("#dc2626", "#ea580c", "#d97706", "#2563eb", "#64748b"):
        assert hexval in css


def test_css_defines_core_components():
    css = _read_asset("report/report.css")
    for cls in (".card", ".chip", ".pill--critical", ".badge-grade", ".sevbar", ".section"):
        assert cls in css
