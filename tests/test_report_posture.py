from cybergraph.report_sections import grade, severity_bar, posture_section


def test_grade_boundaries():
    assert grade([])[0] == "A"
    assert grade([{"risk_score": 39}])[0] == "A"
    assert grade([{"risk_score": 40}])[0] == "B"
    assert grade([{"risk_score": 54}])[0] == "B"
    assert grade([{"risk_score": 55}])[0] == "C"
    assert grade([{"risk_score": 69}])[0] == "C"
    assert grade([{"risk_score": 70}])[0] == "D"
    assert grade([{"risk_score": 84}])[0] == "D"
    assert grade([{"risk_score": 85}])[0] == "E"
    assert grade([{"risk_score": 89}])[0] == "E"
    assert grade([{"risk_score": 90}])[0] == "F"
    # Highest risk drives the grade.
    assert grade([{"risk_score": 10}, {"risk_score": 92}])[0] == "F"


def test_grade_empty_verdict():
    assert "No significant risks" in grade([])[1]


def test_severity_bar_segments():
    html = severity_bar({"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0})
    assert "sevbar" in html
    assert ">2<" in html  # critical count label
    assert "var(--sev-critical)" in html


def test_severity_bar_empty():
    assert "No findings" in severity_bar({})


def test_posture_section_lists_top3():
    risks = [
        {"category": "sqli", "title": "SQL injection", "risk_score": 88, "risk_label": "high", "detail": "d1"},
        {"category": "xss", "title": "XSS", "risk_score": 60, "risk_label": "medium", "detail": "d2"},
        {"category": "sec", "title": "Secret", "risk_score": 30, "risk_label": "low", "detail": "d3"},
        {"category": "x", "title": "Fourth", "risk_score": 10, "risk_label": "low", "detail": "d4"},
    ]
    out = posture_section("repo", {"nodes": 5, "edges": 4, "findings": 3}, risks,
                          {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}, "")
    assert "SQL injection" in out and "XSS" in out and "Secret" in out
    assert "Fourth" not in out  # only top 3
    assert 'id="posture"' in out
