from pathlib import Path

from cybergraph.analysis.python import analyze_python_file

ROUTE = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/u")
def get_user(uid: str):
    return {body}
'''

BENIGN = "def helper():\n    drawChart()\n    reopen_session()\n    writer_pool()\n"

# A sink call inside a nested route handler. `ast.walk(tree)` yields `register`
# and `run` both, and `ast.walk(register)` descends into `run`, so before the
# ownership fix this one call site produced two CALLS edges, two REACHES_SINK
# edges and two findings — the outer pass has none of `run`'s bindings, so it
# abstained beside the inner pass's correct verdict.
NESTED = '''
import os
from fastapi import FastAPI


def register(app):
    @app.get("/run")
    def run(cmd: str):
        os.system("echo " + cmd)

    return run
'''

# A sink call in decorator position. `snapshot_call_sites` walks body
# statements, so this call has no snapshot at all.
DECORATED = '''
import os


@os.system("setup")
def configure():
    return 1
'''


# The canonical Flask shape. `snapshot_call_sites` knows how taint moves between
# names but not which expressions introduce it, so the assignment below looks
# like a clean rebind and used to *clear* `name` before the sink saw it.
REQUEST_LOCAL = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/users")
def users():
    name = request.args.get("name")
    return conn.execute(f"select * from users where name = '{name}'")
'''

# The other half of that trade: a route parameter really reassigned to a literal
# must still clear, or ordinary sanitising code reads as a finding.
SANITIZED_PARAM = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/u")
def get_user(uid: str):
    uid = "1"
    return cursor.execute("SELECT * FROM u WHERE id = " + uid)
'''


def _analyze(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return analyze_python_file(path, tmp_path)


def test_parameterized_query_is_not_a_finding(tmp_path):
    _, edges, findings = _analyze(
        tmp_path, ROUTE.format(body='cursor.execute("SELECT * FROM u WHERE id = ?", (uid,))')
    )
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges), "inventory edge must survive"


def test_concatenated_query_is_a_finding(tmp_path):
    _, _, findings = _analyze(
        tmp_path, ROUTE.format(body='cursor.execute("SELECT * FROM u WHERE id = " + uid)')
    )
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"]
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-89"


def test_unverifiable_query_is_a_distinct_lower_severity_rule(tmp_path):
    _, _, findings = _analyze(tmp_path, ROUTE.format(body="cursor.execute(build(uid))"))
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC-UNVERIFIED"]
    assert findings[0].severity == "medium"
    assert "could not confirm" in findings[0].message


def test_benign_names_produce_neither(tmp_path):
    _, edges, findings = _analyze(tmp_path, BENIGN)
    assert findings == []
    assert not any(e.kind == "REACHES_SINK" for e in edges)


def test_nested_function_sink_is_attributed_to_one_function_only(tmp_path):
    _, edges, findings = _analyze(tmp_path, NESTED)
    assert [f.rule_id for f in findings] == ["CG-CMD-EXEC"]
    assert [e.kind for e in edges if e.kind == "REACHES_SINK"] == ["REACHES_SINK"]
    assert [e.source for e in edges if e.kind == "CALLS" and e.target == "os.system"] == [
        "app.py::run"
    ]


def test_sink_in_a_decorator_abstains_rather_than_clearing(tmp_path):
    _, edges, findings = _analyze(tmp_path, DECORATED)
    assert [f.rule_id for f in findings] == ["CG-CMD-EXEC-UNVERIFIED"]
    assert findings[0].severity == "medium"
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_request_value_read_into_a_local_still_reaches_the_sink(tmp_path):
    _, _, findings = _analyze(tmp_path, REQUEST_LOCAL)
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"]
    assert findings[0].severity == "high"


def test_route_parameter_reassigned_to_a_literal_is_cleared(tmp_path):
    _, edges, findings = _analyze(tmp_path, SANITIZED_PARAM)
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_custom_sink_matches_exactly_and_is_not_a_substring(tmp_path):
    source = ROUTE.format(body="audit_write(uid)") + (
        "\n\ndef other(uid):\n    audit_write_later(uid)\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    _, edges, findings = analyze_python_file(path, tmp_path, custom_sinks=("audit_write",))
    assert [e.target for e in edges if e.kind == "REACHES_SINK"] == ["audit_write"]
    assert [f.rule_id for f in findings] == ["CG-CUSTOM-SINK"]
