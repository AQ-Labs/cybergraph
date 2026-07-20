from cybergraph.history import Delta
from cybergraph.report_sections import delta_strip


def test_delta_hidden_first_scan():
    assert delta_strip(Delta(is_first=True), None) == ""


def test_delta_hidden_when_none():
    assert delta_strip(None, None) == ""


def test_delta_renders_counts_and_date():
    d = Delta(is_first=False, new=["a", "b"], fixed=["c"], regressed=["d"], persisting=["e", "f", "g"])
    out = delta_strip(d, "2026-07-19T10:00:00+00:00")
    assert "2 new" in out and "1 fixed" in out and "1 regressed" in out and "3 persisting" in out
    assert "2026-07-19" in out
