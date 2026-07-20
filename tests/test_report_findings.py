from cybergraph.report_sections import findings_table


def _rows(n):
    return [
        {"severity": "high", "rule_id": f"R{i}", "message": "m", "file_path": "a.py",
         "line_start": i, "tool": "t"}
        for i in range(n)
    ]


def test_footer_when_capped():
    out = findings_table(_rows(100), total_findings=250)
    assert "top 100" in out.lower() and "250" in out
    assert "cybergraph sarif" in out


def test_footer_when_all_shown():
    out = findings_table(_rows(4), total_findings=4)
    assert "all 4" in out.lower()


def test_rows_carry_severity_rank_for_sort():
    out = findings_table(_rows(1), total_findings=1)
    assert "data-sev-rank" in out


def test_empty_findings_message():
    assert "No findings" in findings_table([], total_findings=0)
