from cybergraph.security.sinks import all_sinks, lookup_sink


def test_exact_qualified_name_matches():
    sink = lookup_sink("subprocess.run", "python")
    assert sink is not None
    assert sink.vuln_class == "command"
    assert sink.shell == "conditional"


def test_shell_inherent_apis_are_marked():
    assert lookup_sink("os.system", "python").shell == "inherent"
    assert lookup_sink("os.popen", "python").shell == "inherent"


def test_bare_callee_matches_when_receiver_unknown():
    assert lookup_sink("cursor.execute", "python").vuln_class == "sql"


def test_substring_no_longer_matches():
    for name in ("drawChart", "reopen_session", "writer_pool", "connect_retry_helper"):
        assert lookup_sink(name, "python") is None, name


def test_unknown_language_returns_none():
    assert lookup_sink("subprocess.run", "cobol") is None


def test_registry_is_internally_consistent():
    classes = {"sql", "command", "code", "deserialize", "path", "template", "custom"}
    banned = {"sink", "taint", "cwe", "sarif", "entrypoint"}
    for sink in all_sinks():
        assert sink.vuln_class in classes, sink.name
        assert sink.shell in {"none", "inherent", "conditional"}, sink.name
        assert sink.plain and not any(w in sink.plain.lower() for w in banned), sink.name
        if sink.shell != "none":
            assert sink.vuln_class == "command", sink.name
