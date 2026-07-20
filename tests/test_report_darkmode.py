from cybergraph.visualize import _read_asset


def test_risk_and_path_cards_use_tokens_not_hardcoded_white():
    css = _read_asset("report/report.css")
    # The .risk-card and .path rules must not force a literal white background.
    for rule_name in (".risk-card", ".path"):
        idx = css.find(rule_name + " {")
        assert idx != -1, rule_name
        block = css[idx:css.find("}", idx)]
        assert "#fff" not in block and "white" not in block, f"{rule_name} still hard-codes white"


def test_dark_overrides_present():
    css = _read_asset("report/report.css")
    assert '[data-theme="dark"]' in css and "prefers-color-scheme: dark" in css
