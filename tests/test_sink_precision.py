from pathlib import Path

import pytest

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

# A route parameter really reassigned to a literal must still clear, or ordinary
# sanitising code reads as a finding. This clears through `bindings`, not
# through taint: `uid = "1"` makes the binding LITERAL and `classify_expr` folds
# `"..." + uid` to LITERAL, so `_assess_sql` returns safe on its construction
# short-circuit before it consults taint at all. Stated because an earlier
# revision cited this test as pinning a taint-clearing rule it never exercised;
# `test_a_request_read_into_a_same_named_parameter_is_still_tainted` is what
# pins that.
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


# --- Task 5, fix round 1: the taint model ------------------------------------

FLASK = "from flask import Flask, request\napp = Flask(__name__)\n\n"


def _flask(tmp_path: Path, body: str):
    return _analyze(tmp_path, FLASK + body)


@pytest.mark.parametrize(
    "body,expected",
    [
        (
            "@app.route('/u')\n"
            "def u(uid):\n"
            "    uid = request.args.get('uid')\n"
            "    return conn.execute('select * from users where id = ' + uid)\n",
            "CG-SQL-EXEC",
        ),
        (
            "@app.route('/u')\n"
            "def u(uid):\n"
            "    uid = request.form['uid']\n"
            "    return conn.execute('select * from users where id = ' + uid)\n",
            "CG-SQL-EXEC",
        ),
        (
            "import os\n"
            "@app.route('/u')\n"
            "def u(cmd):\n"
            "    cmd = request.args.get('cmd')\n"
            "    os.system('echo ' + cmd)\n",
            "CG-CMD-EXEC",
        ),
    ],
)
def test_a_request_read_into_a_same_named_parameter_is_still_tainted(
    tmp_path: Path, body: str, expected: str
) -> None:
    """Re-reading the request into a parameter of the same name is ordinary code.

    An earlier revision re-asserted body-discovered taint on top of the
    flow-sensitive snapshot and excluded route parameters from it, so this shape
    read *safe* while renaming the parameter reported high. The name of a local
    cannot decide whether a request read happened.
    """
    _nodes, _edges, findings = _flask(tmp_path, body)
    assert [f.rule_id for f in findings] == [expected], [f.rule_id for f in findings]


@pytest.mark.parametrize(
    "body",
    [
        # Inline: no local is bound at all.
        "@app.route('/u')\n"
        "def u():\n"
        '    return conn.execute("select * from u where n = \'" + request.args.get("n") + "\'")\n',
        # A `for` target.
        "@app.route('/u')\n"
        "def u():\n"
        "    for name in request.args.getlist('name'):\n"
        "        conn.execute('select ' + name)\n",
        # A walrus.
        "@app.route('/u')\n"
        "def u():\n"
        "    if (name := request.args.get('name')):\n"
        "        conn.execute('select ' + name)\n",
        # Augmented assignment.
        "@app.route('/u')\n"
        "def u():\n"
        "    q = 'select '\n"
        "    q += request.args.get('name')\n"
        "    return conn.execute(q)\n",
        # A comprehension generator.
        "@app.route('/u')\n"
        "def u():\n"
        "    return [conn.execute('select ' + x) for x in request.args.getlist('a')]\n",
        # `with ... as`.
        "@app.route('/u')\n"
        "def u():\n"
        "    with request.files['f'] as fh:\n"
        "        return conn.execute('select ' + fh)\n",
        # Tuple unpacking.
        "@app.route('/u')\n"
        "def u():\n"
        "    name, _rest = request.args.get('name'), 1\n"
        "    return conn.execute('select ' + name)\n",
        # Starred unpacking.
        "@app.route('/u')\n"
        "def u():\n"
        "    first, *_rest = request.args.getlist('a')\n"
        "    return conn.execute('select ' + first)\n",
    ],
)
def test_taint_is_found_in_every_binding_form_not_only_assignment(
    tmp_path: Path, body: str
) -> None:
    """Assignment is one of eight ways a request read reaches a sink here.

    Introduction used to live in a pass that modelled `Assign` and `AnnAssign`
    only, so each of these produced no finding whatever — an unrecognised
    argument is not a tainted one, and an untainted argument was cleared
    outright.
    """
    _nodes, edges, findings = _flask(tmp_path, body)
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


@pytest.mark.parametrize(
    "body",
    [
        # The sink runs before the read that would have tainted its argument.
        "@app.route('/u')\n"
        "def u():\n"
        "    name = default_name()\n"
        '    rows = conn.execute("select * from t where a = \'" + name + "\'")\n'
        "    name = request.args.get('name')\n"
        "    return rows, name\n",
        # The read is overwritten by a clean value before the sink runs.
        "@app.route('/u')\n"
        "def u():\n"
        "    name = request.args.get('name')\n"
        "    name = default_name()\n"
        '    return conn.execute("select * from t where a = \'" + name + "\'")\n',
    ],
)
def test_taint_respects_statement_order(tmp_path: Path, body: str) -> None:
    """A name-keyed map of the whole function cannot say *when* a name was tainted.

    Seeding one at function entry reported the first shape here — a call the
    user's data provably cannot reach, because it runs first — as high.
    """
    _nodes, edges, findings = _flask(tmp_path, body)
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


CONFINE_INLINE = '''
import os
from fastapi import FastAPI
app = FastAPI()

@app.get("/f")
def f(name: str):
    return open("/data/" + os.path.basename(name))
'''

CONFINE_REBIND = '''
import os
from fastapi import FastAPI
app = FastAPI()

@app.get("/f")
def f(name: str):
    name = os.path.basename(name)
    return open("/data/" + name)
'''

CONFINE_REBIND_SQL = '''
import os
from fastapi import FastAPI
app = FastAPI()

@app.get("/f")
def f(name: str):
    name = os.path.basename(name)
    return conn.execute("select " + name)
'''

CONFINE_REBIND_UNRECOGNISED = '''
import my_utils
from fastapi import FastAPI
app = FastAPI()

@app.get("/f")
def f(name: str):
    name = my_utils.basename(name)
    return open("/data/" + name)
'''


def test_a_confining_rebind_clears_a_path_exactly_as_the_inline_spelling_does(
    tmp_path: Path,
) -> None:
    for source in (CONFINE_INLINE, CONFINE_REBIND):
        _nodes, edges, findings = _analyze(tmp_path, source)
        assert findings == [], [f.rule_id for f in findings]
        assert any(e.kind == "REACHES_SINK" for e in edges)


def test_confinement_is_scoped_to_the_class_it_confines_and_to_a_known_receiver(
    tmp_path: Path,
) -> None:
    """`basename` confines a path. It does nothing whatever for SQL.

    Both halves matter. Clearing taint in the provenance walk would have made
    the first case safe, because that walk has no vulnerability class to
    consult; and an unrecognised receiver must not be able to grant safety by
    sharing a name.
    """
    _nodes, _edges, sql_findings = _analyze(tmp_path, CONFINE_REBIND_SQL)
    assert [f.rule_id for f in sql_findings] == ["CG-SQL-EXEC"]

    _nodes, _edges, path_findings = _analyze(tmp_path, CONFINE_REBIND_UNRECOGNISED)
    assert [f.rule_id for f in path_findings] == ["CG-PATH-TRAVERSAL"]


def test_a_local_named_like_a_source_is_not_a_source(tmp_path: Path) -> None:
    """`query` is in `SOURCE_KEYWORDS`, and locals get called `query`.

    Recognising a read of user input at a sink argument is what catches the
    inline shapes above. Applying it to a bare name as well contradicts the
    flow-sensitive taint map and made an allowlisted, composed query a **high**
    finding.
    """
    source = (
        "COLS = 'id, name'\n"
        "def report():\n"
        "    query = 'select ' + COLS + ' from t'\n"
        "    return cursor.execute(query)\n"
    )
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)
