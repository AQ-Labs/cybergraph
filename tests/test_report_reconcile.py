from cybergraph.history import Delta
from cybergraph.visualize import (
    _grade,
    _severity_bar,
    _posture_section,
    _delta_strip,
    _findings_footer,
)


def test_grade_boundaries():
    assert _grade([])[0] == "A"
    assert _grade([{"risk_score": 39}])[0] == "A"
    assert _grade([{"risk_score": 40}])[0] == "B"
    assert _grade([{"risk_score": 54}])[0] == "B"
    assert _grade([{"risk_score": 55}])[0] == "C"
    assert _grade([{"risk_score": 69}])[0] == "C"
    assert _grade([{"risk_score": 70}])[0] == "D"
    assert _grade([{"risk_score": 84}])[0] == "D"
    assert _grade([{"risk_score": 85}])[0] == "E"
    assert _grade([{"risk_score": 89}])[0] == "E"
    assert _grade([{"risk_score": 90}])[0] == "F"
    assert _grade([{"risk_score": 10}, {"risk_score": 92}])[0] == "F"


def test_grade_empty_verdict():
    assert "No significant risks" in _grade([])[1]


def test_severity_bar_segments():
    out = _severity_bar({"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0})
    assert "sevbar" in out
    assert ">2<" in out
    assert "#dc2626" in out  # critical color, inline


def test_severity_bar_empty():
    assert "No findings" in _severity_bar({})


def test_posture_section_present():
    out = _posture_section(
        {"nodes": 5, "edges": 4, "findings": 3, "attack_paths": 1},
        [{"category": "sqli", "title": "SQL injection", "risk_score": 88,
          "risk_label": "high", "detail": "d"}],
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "",
    )
    assert 'id="posture"' in out
    assert "SQL injection" not in out  # posture links to the risk strip, doesn't duplicate cards
    assert ">B<" in out or "badge-grade" in out  # grade badge present


def test_delta_hidden_first_scan():
    assert _delta_strip(Delta(is_first=True), None) == ""


def test_delta_hidden_when_none():
    assert _delta_strip(None, None) == ""


def test_delta_renders_counts_and_date():
    d = Delta(is_first=False, new=["a", "b"], fixed=["c"], regressed=["d"],
              persisting=["e", "f", "g"])
    out = _delta_strip(d, "2026-07-19T10:00:00+00:00")
    assert "2 new" in out and "1 fixed" in out and "1 regressed" in out and "3 persisting" in out
    assert "2026-07-19" in out
    assert "Since since" not in out


def test_findings_footer_capped():
    out = _findings_footer(100, 250)
    assert "top 100" in out.lower() and "250" in out
    assert "cybergraph sarif" in out


def test_findings_footer_all_shown():
    assert "all 4" in _findings_footer(4, 4).lower()
