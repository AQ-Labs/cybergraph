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


# R7-6 (Important, live false positive): `open` was `bare=True`, so any
# `x.open(...)` matched it — `webbrowser.open(report_path.as_uri())` in this
# repository's own `cli.py` reported CG-PATH-TRAVERSAL at high, and the CI SARIF
# filter (`^CG-.*SINK-CALL$`) does not drop it. `bare` is for receivers that
# cannot be resolved without type inference; `open` is spelled unqualified.


def test_open_no_longer_matches_an_arbitrary_receiver():
    for name in ("webbrowser.open", "path.open", "socket.open", "self.open", "db.open"):
        assert lookup_sink(name, "python") is None, name


def test_open_still_matches_unqualified_and_the_module_spellings():
    for name in ("open", "io.open", "codecs.open"):
        sink = lookup_sink(name, "python")
        assert sink is not None, name
        assert sink.vuln_class == "path", name


def test_bare_matching_survives_for_the_sinks_that_need_it():
    """`execute` and `raw` cannot resolve their receivers, and SQL detection
    rests on them: `cursor.execute` and `User.objects.raw` must keep matching."""
    for name, tail in (
        ("cursor.execute", "execute"),
        ("conn.execute", "execute"),
        ("cur.executemany", "executemany"),
        ("conn.executescript", "executescript"),
        ("User.objects.raw", "raw"),
    ):
        sink = lookup_sink(name, "python")
        assert sink is not None, name
        assert sink.name == tail, name
        assert sink.vuln_class == "sql", name


def test_registry_is_internally_consistent():
    classes = {"sql", "command", "code", "deserialize", "path", "template", "custom"}
    banned = {"sink", "taint", "cwe", "sarif", "entrypoint"}
    for sink in all_sinks():
        assert sink.vuln_class in classes, sink.name
        assert sink.shell in {"none", "inherent", "conditional"}, sink.name
        assert sink.plain and not any(w in sink.plain.lower() for w in banned), sink.name
        if sink.shell != "none":
            assert sink.vuln_class == "command", sink.name
