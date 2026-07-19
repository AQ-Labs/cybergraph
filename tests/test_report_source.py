# tests/test_report_source.py
from pathlib import Path

from cybergraph.report_source import attach_source_snippets


def _graph(repo: Path, extra=None):
    node = {"id": "app.py::h", "file": "app.py", "line": 3, "findings": []}
    if extra:
        node.update(extra)
    return {"nodes": [node]}


def _write(repo: Path, name: str, text: str):
    (repo / name).write_text(text, encoding="utf-8")


def test_attaches_highlighted_snippet_for_finding_node(tmp_path: Path):
    _write(tmp_path, "app.py", "a = 1\nb = 2\nrun(x)\nc = 3\nd = 4\n")
    g = _graph(tmp_path, {"findings": [{"severity": "high", "rule_id": "CG-X", "message": "m"}]})
    attach_source_snippets(tmp_path, g, context=1)
    snip = g["nodes"][0]["snippet"]
    assert snip["file"] == "app.py"
    nums = [ln["n"] for ln in snip["lines"]]
    assert nums == [2, 3, 4]  # context=1 around line 3, clamped
    hl = [ln for ln in snip["lines"] if ln["highlight"]]
    assert len(hl) == 1 and hl[0]["n"] == 3 and "run(x)" in hl[0]["text"]


def test_start_of_file_clamps_without_negative(tmp_path: Path):
    _write(tmp_path, "app.py", "run(x)\nb = 2\n")
    g = _graph(
        tmp_path, {"line": 1, "findings": [{"rule_id": "CG-X", "severity": "high", "message": "m"}]}
    )
    attach_source_snippets(tmp_path, g, context=3)
    assert [ln["n"] for ln in g["nodes"][0]["snippet"]["lines"]] == [1, 2]


def test_html_is_escaped(tmp_path: Path):
    _write(tmp_path, "app.py", "x = '<b>&</b>'\n")
    g = _graph(
        tmp_path, {"line": 1, "findings": [{"rule_id": "CG-X", "severity": "high", "message": "m"}]}
    )
    attach_source_snippets(tmp_path, g)
    text = g["nodes"][0]["snippet"]["lines"][0]["text"]
    assert "&lt;b&gt;" in text and "<b>" not in text


def test_secret_finding_line_is_redacted(tmp_path: Path):
    _write(tmp_path, "Dockerfile", "FROM x\nENV API_KEY=supersecretvalue\n")
    g = _graph(tmp_path, {"id": "Dockerfile", "file": "Dockerfile", "line": 2,
                          "findings": [{"rule_id": "CG-DOCKER-SECRET", "severity": "critical",
                                         "message": "m"}]})
    attach_source_snippets(tmp_path, g, context=0)
    line = g["nodes"][0]["snippet"]["lines"][0]
    assert line["highlight"] is True
    assert "supersecretvalue" not in line["text"]
    assert "redacted" in line["text"].lower()


def test_node_without_finding_or_file_gets_no_snippet(tmp_path: Path):
    g = {"nodes": [{"id": "n", "file": "", "line": 0, "findings": []},
                   {"id": "m", "file": "missing.py", "line": 5,
                    "findings": [{"rule_id": "R", "severity": "low", "message": "x"}]}]}
    attach_source_snippets(tmp_path, g)
    assert "snippet" not in g["nodes"][0]  # no file
    assert "snippet" not in g["nodes"][1]  # file missing -> best-effort skip


def test_max_nodes_cap(tmp_path: Path):
    _write(tmp_path, "app.py", "run(x)\n")
    nodes = [{"id": f"n{i}", "file": "app.py", "line": 1,
              "findings": [{"rule_id": "R", "severity": "low", "message": "x"}]} for i in range(5)]
    g = {"nodes": nodes}
    attach_source_snippets(tmp_path, g, context=0, max_nodes=2)
    assert sum("snippet" in n for n in g["nodes"]) == 2
