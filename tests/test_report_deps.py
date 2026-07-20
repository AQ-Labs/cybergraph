from cybergraph.report_sections import vulnerable_dependencies_table


def test_pretty_prints_json_evidence():
    rows = [{"vulnerability": "CVE-1", "dependency": "left-pad",
             "properties": '{"epss": 0.4, "kev": true}'}]
    out = vulnerable_dependencies_table(rows)
    assert '  "epss"' in out  # two-space indent proves json.dumps(indent=2) ran


def test_falls_back_on_non_json():
    rows = [{"vulnerability": "CVE-2", "dependency": "req", "properties": "not-json{"}]
    out = vulnerable_dependencies_table(rows)
    assert "not-json{" in out  # escaped raw, no crash


def test_empty_deps_message():
    assert "No vulnerable dependency" in vulnerable_dependencies_table([])
