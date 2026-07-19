# tests/test_report_banner.py
from cybergraph.visualize import _truncation_banner


def test_banner_when_truncated():
    html = _truncation_banner({"truncated": True, "nodes": [0] * 600, "counts": {"nodes": 1500}})
    assert "600" in html and "1500" in html and "max-nodes" in html


def test_no_banner_when_not_truncated():
    assert _truncation_banner({"truncated": False, "nodes": [0] * 10, "counts": {"nodes": 10}}) == ""
