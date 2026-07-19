# tests/test_history_record.py
from cybergraph.history import fingerprint


def test_fingerprint_is_line_independent_and_tool_sensitive():
    a = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    b = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    assert a == b and len(a) == 40  # sha1 hex, stable regardless of line
    # different tool -> different identity (distinct evidence sources)
    assert fingerprint("CG-SINK", "semgrep", "app.py", "reaches sink `db.execute`") != a
    # different file -> different identity
    assert fingerprint("CG-SINK", "cybergraph", "other.py", "reaches sink `db.execute`") != a
