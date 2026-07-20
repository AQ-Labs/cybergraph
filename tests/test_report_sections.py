from cybergraph.report_sections import safe_section, truncation_banner


def test_safe_section_returns_card_on_error():
    def boom():
        raise ValueError("nope")
    out = safe_section(boom)
    assert "section unavailable" in out.lower()


def test_safe_section_passes_through_ok():
    assert safe_section(lambda x: f"<p>{x}</p>", "hi") == "<p>hi</p>"


def test_truncation_banner_moved():
    assert truncation_banner({"truncated": False, "nodes": [], "counts": {"nodes": 0}}) == ""
