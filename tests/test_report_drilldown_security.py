"""Security regression tests for report source drill-down: secrets must never leak."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.report_source import _redact_line, attach_source_snippets
from cybergraph.visualize import generate_html_report


# --- unit: content-based redaction ------------------------------------------
def test_keyword_assignment_value_is_redacted():
    text, red = _redact_line('ENV AWS_SECRET_ACCESS_KEY=AKIAtotallyrealsecret123')
    assert red is True
    assert "AKIAtotallyrealsecret123" not in text
    assert "redacted" in text.lower()


def test_colon_delimited_secret_is_redacted():
    text, red = _redact_line("    password: hunter2supersecret")
    assert red is True and "hunter2supersecret" not in text


def test_aws_key_without_keyword_is_redacted():
    text, red = _redact_line('x = "AKIAABCDEFGH12345678"')
    assert red is True and "AKIAABCDEFGH12345678" not in text


def test_ordinary_code_is_not_over_redacted():
    for line in ["    return db.execute('select ' + q)", "x = 1", "q = request.query['q']"]:
        text, red = _redact_line(line)
        assert red is False and text == line


def test_function_call_value_on_secret_key_is_not_redacted():
    # A secret-named key assigned from an expression/call is legit code, not a secret.
    line = '    token = request.headers.get("authorization")'
    text, red = _redact_line(line)
    assert red is False and text == line


def test_quoted_literal_on_secret_key_is_redacted():
    text, red = _redact_line('    api_token = "abc123realtokenvalue"')
    assert red is True and "abc123realtokenvalue" not in text


# --- unit: anchoring on the finding line, not the node line -----------------
def test_snippet_anchors_on_finding_line_not_node_line(tmp_path: Path):
    (tmp_path / "f.py").write_text(
        "\n".join(f"line{n}" for n in range(1, 11)) + "\n", encoding="utf-8"
    )
    g = {"nodes": [{
        "id": "f.py", "file": "f.py", "line": 1,   # File node at line 1
        "findings": [{"rule_id": "CG-X", "severity": "high", "message": "m", "line": 5}],
    }]}
    attach_source_snippets(tmp_path, g, context=2)
    snip = g["nodes"][0]["snippet"]
    assert [ln["n"] for ln in snip["lines"]] == [3, 4, 5, 6, 7]      # window around line 5
    assert [ln["n"] for ln in snip["lines"] if ln["highlight"]] == [5]


def test_secret_on_context_line_near_nonsecret_finding_is_redacted(tmp_path: Path):
    # SQL-sink finding at line 3; a hardcoded key sits on context line 2.
    (tmp_path / "app.py").write_text(
        'def h(q):\n    API_KEY = "sk-livesecretvalue999"\n    return db.execute(q)\n',
        encoding="utf-8",
    )
    g = {"nodes": [{
        "id": "app.py::h", "file": "app.py", "line": 3,
        "findings": [{"rule_id": "CG-SINK-CALL", "severity": "high", "message": "sql", "line": 3}],
    }]}
    attach_source_snippets(tmp_path, g, context=3)
    joined = " ".join(ln["text"] for ln in g["nodes"][0]["snippet"]["lines"])
    assert "sk-livesecretvalue999" not in joined  # secret on a CONTEXT line still redacted


# --- end-to-end: the report file itself must not contain the secret ----------
def test_dockerfile_secret_absent_from_generated_report(tmp_path: Path):
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12\nENV AWS_SECRET_ACCESS_KEY=AKIAtotallyrealsecret123\nRUN echo hi\n",
        encoding="utf-8",
    )
    build_graph(repo)
    html = generate_html_report(repo, tmp_path / "r.html", with_source=True).read_text(
        encoding="utf-8"
    )
    assert "AKIAtotallyrealsecret123" not in html   # the whole point
    assert "redacted" in html                        # redaction actually fired
