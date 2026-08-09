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
    # Pin the edge's endpoints, not the literal it is filtered against: the old
    # `[e.kind ... if e.kind == "REACHES_SINK"] == ["REACHES_SINK"]` compared a
    # list against the very value it filtered on, so it could only ever be a
    # count of one and pinned nothing about source or target.
    reaches = [(e.source, e.target) for e in edges if e.kind == "REACHES_SINK"]
    assert reaches == [("app.py::run", "os.system")], reaches
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


def test_a_bare_configured_sink_name_matches_a_receiver_call(tmp_path: Path) -> None:
    """A configured method name has no other spelling available to the user.

    Registry sinks marked `bare` already match a receiver call; a custom sink
    lost both the finding and the `REACHES_SINK` edge, so the inventory a
    reviewer inspects went quiet along with the report.
    """
    source = ROUTE.format(body="auditor.audit_write(uid)")
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    _nodes, edges, findings = analyze_python_file(path, tmp_path, custom_sinks=("audit_write",))

    assert [e.target for e in edges if e.kind == "REACHES_SINK"] == ["auditor.audit_write"]
    assert [f.rule_id for f in findings] == ["CG-CUSTOM-SINK"]


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


# One dot deeper than the bare name above, which is where the same defect
# survived: the chain *text* contains a source keyword, so the member was read
# as user input. Every receiver here is an ordinary object — a config, an
# argparse namespace, `self`, a session — and every member name merely contains
# a keyword rather than being one. Each is paired below with the framework read
# it must not be allowed to take down with it.
LOOKALIKE_MEMBERS = [
    ("import subprocess\n"
     "def go(cfg):\n"
     "    return subprocess.run('ls ' + cfg.input_dir, shell=True)\n"),
    ("def go(args):\n"
     "    return open(args.input)\n"),
    ("class C:\n"
     "    def go(self):\n"
     "        return open(self.input_path)\n"),
    ("class C:\n"
     "    def go(self):\n"
     "        return cursor.execute(f'select {self.query}')\n"),
    ("import os\n"
     "def go(settings):\n"
     "    return open(settings.form_dir + '/x')\n"),
    ("import os\n"
     "def go(repo):\n"
     "    return os.system('echo ' + repo.body_text)\n"),
    ("def go(query_builder):\n"
     "    return cursor.execute('select ' + query_builder.build())\n"),
    # An outbound HTTP call, not an inbound request: `request` is the member
    # being *called*, with nothing read out of it.
    ("import os\n"
     "def go(session, url):\n"
     "    return os.system('echo ' + session.request('GET', url))\n"),
    # ...and the way that call is actually written. The pin above was defeated
    # by appending `.text`, because the chain then *has* a trailing segment and
    # the rule only required one to exist. What settles it is that `request` is
    # the segment being called, which no suffix changes.
    ("import os\n"
     "def go(session, url):\n"
     "    return os.system('echo ' + session.request('GET', url).text)\n"),
    # An HTTP *client* wrapper, and a mock. `request` sits in a non-final
    # position in all three, so position alone never separated them from
    # `self.request.body`; the member the chain ends in does.
    ("class C:\n"
     "    def go(self):\n"
     "        return cursor.execute('select ' + self.request.timeout)\n"),
    ("def go(obj):\n"
     "    return cursor.execute('select ' + obj.request.call_args)\n"),
    ("def go(req):\n"
     "    return cursor.execute('select ' + req.url)\n"),
    ("def go(webhook):\n"
     "    return cursor.execute('select ' + webhook.url)\n"),
    # A bare call that merely shares a name with a source keyword. `query` is
    # an ordinary helper name; so is `form`, `body` and `params`. Every one of
    # these was a critical finding.
    ("def go(name):\n"
     "    return cursor.execute('select ' + query(name))\n"),
    ("import os\n"
     "def go(name):\n"
     "    return os.system('echo ' + body(name))\n"),
    ("import flask\n"
     "def go():\n"
     "    return cursor.execute('select ' + flask.query(1))\n"),
    # The process environment is not the CGI environment. Only a key that
    # names a request field makes `environ` a request.
    ("import os\n"
     "def go(rev):\n"
     "    return cursor.execute('select ' + os.environ['GIT_DIR'])\n"),
    # Word matching must not take an identifier that *counts* requests.
    ("class C:\n"
     "    def go(self):\n"
     "        return cursor.execute('select ' + self.request_count.render())\n"),
]

FRAMEWORK_READS = [
    ("from flask import request\n"
     "def go():\n"
     "    return cursor.execute('select ' + request.args.get('u'))\n"),
    ("from flask import request\n"
     "def go():\n"
     "    return cursor.execute('select ' + request.form['u'])\n"),
    ("from flask import request\n"
     "def go():\n"
     "    return cursor.execute('select ' + request.cookies.get('c'))\n"),
    ("import flask\n"
     "def go():\n"
     "    return cursor.execute('select ' + flask.request.args.get('u'))\n"),
    # Django's spelling, and the receiver reached through `self`.
    ("def go(request):\n"
     "    return cursor.execute('select ' + request.GET.get('u'))\n"),
    ("class H:\n"
     "    def go(self):\n"
     "        return cursor.execute('select ' + self.request.body)\n"),
    ("def go(req):\n"
     "    return cursor.execute('select ' + req.query_params.get('u'))\n"),
    # Not a web request at all, and both must survive the anchoring.
    ("import os, sys\n"
     "def go():\n"
     "    return os.system('echo ' + sys.argv[1])\n"),
    ("import os\n"
     "def go():\n"
     "    return os.system('echo ' + input('cmd: '))\n"),
    # A request object under any name but `request`/`req`. Renaming it used to
    # defeat the detector outright, which is a silent miss on every handler
    # that spells the variable differently.
    ("def go(http_request):\n"
     "    return cursor.execute('select ' + http_request.args.get('u'))\n"),
    ("def go(request_obj):\n"
     "    return cursor.execute('select ' + request_obj.form['u'])\n"),
    # Members distinctive enough to name an inbound API on their own, so the
    # receiver's name does not have to be recognised: Starlette/DRF, Django
    # forms, cgi.FieldStorage and Tornado.
    ("def go(obj):\n"
     "    return cursor.execute('select ' + obj.query_params.get('u'))\n"),
    ("def go(form):\n"
     "    return cursor.execute('select ' + form.cleaned_data['u'])\n"),
    ("import cgi\n"
     "def go(form):\n"
     "    return cursor.execute('select ' + form.getvalue('u'))\n"),
    ("class H:\n"
     "    def post(self):\n"
     "        return cursor.execute('select ' + self.get_body_argument('u'))\n"),
    # `http.server.BaseHTTPRequestHandler`: the handler *is* the request.
    ("class H:\n"
     "    def do_GET(self):\n"
     "        return cursor.execute('select ' + self.headers.get('X-Q'))\n"),
    # The protocol-level containers: bare WSGI, ASGI, and a webhook payload.
    ("def app(environ, start_response):\n"
     "    return cursor.execute('select ' + environ['QUERY_STRING'])\n"),
    ("import os\n"
     "def go():\n"
     "    return cursor.execute('select ' + os.environ['HTTP_USER_AGENT'])\n"),
    ("async def app(scope, receive, send):\n"
     "    return cursor.execute('select ' + scope['query_string'])\n"),
    ("def handler(event, context):\n"
     "    return cursor.execute('select ' + event['body'])\n"),
    # A framework source *factory*, which is spelled with a capital and is the
    # only reason a bare call can be a source at all.
    ("from fastapi import Query\n"
     "def go():\n"
     "    return cursor.execute('select ' + Query(None))\n"),
]


@pytest.mark.parametrize("source", LOOKALIKE_MEMBERS)
def test_a_member_named_like_a_source_is_not_a_source(tmp_path: Path, source: str) -> None:
    """A dotted chain must *name* a source, not merely contain one.

    The bare-name exclusion above stopped at one segment, so anything one dot
    deeper — `cfg.input_dir`, `self.query`, `session.cookie_jar` — was still
    matched by substring and became a high or critical finding on ordinary
    configuration objects. This is the same substring defect the sink registry
    was rewritten to remove, on the source side.
    """
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert [f.rule_id for f in findings] == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


@pytest.mark.parametrize("source", FRAMEWORK_READS)
def test_a_framework_read_is_still_a_source(tmp_path: Path, source: str) -> None:
    """The other half of the anchoring, asserted in the same breath.

    Narrowing a source rule fails *open* — a source dropped is a vulnerability
    missed, and nothing in the corpus or the gate would say so. These are the
    reads the anchoring exists to keep, so they are pinned beside the lookalikes
    rather than in a separate file where the two can drift apart.
    """
    _nodes, _edges, findings = _analyze(tmp_path, source)
    assert findings != [], "framework read stopped being a source"
    assert all(not f.rule_id.endswith("-UNVERIFIED") for f in findings), (
        [f.rule_id for f in findings]
    )


def test_a_string_literal_is_not_a_source_in_any_binding_form(tmp_path: Path) -> None:
    """The introduction side scanned unparsed *text*, so a literal was a source.

    `["body.txt"]` contains `body`, so binding `v` from it introduced taint and
    the path sink below reported high. The same scan is what makes `for`,
    walrus, `+=` and `with ... as` see a real request read, so it could not
    simply be deleted — it had to become structural.
    """
    source = (
        "def report():\n"
        "    for v in ['body.txt']:\n"
        "        open('/data/' + v)\n"
    )
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_a_bare_name_at_a_sink_argument_is_left_to_the_taint_map(tmp_path: Path) -> None:
    """The bare-name exclusion, pinned at the one name anchoring cannot subsume.

    Once a chain has to *name* a source, `query` and `params` are excluded by
    the anchoring itself, so the case the original exclusion defended no longer
    reaches it. What is left is a name that **is** an input value — `argv` —
    where the exclusion is the only thing keeping a plain parameter from being
    a critical finding by its spelling. Whether a local or a parameter carries
    user data is the flow-sensitive map's answer, and a second answer read off
    the variable's name can only contradict it.
    """
    source = (
        "import os\n"
        "def report(argv):\n"
        "    return os.system(argv)\n"
    )
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_a_request_bound_to_a_local_still_introduces_taint(tmp_path: Path) -> None:
    """`r = request` is the one place a bare name must count as a source.

    The taint map cannot answer it — `request` is a module global it never
    bound — so excluding bare names outright at the *introduction* site would
    lose the flow. At a sink argument the map does answer it, which is why the
    exclusion holds there and not here.
    """
    source = (
        "from flask import request\n"
        "def report():\n"
        "    r = request\n"
        "    return cursor.execute('select ' + r.args.get('u'))\n"
    )
    _nodes, _edges, findings = _analyze(tmp_path, source)
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"]


# The lookalikes above are read *inline* at the sink, where `user_input_nodes`
# governs and already rejects them. The regression lived one step earlier: a
# lookalike bound to a *local* first, where `reads_user_input` introduces taint.
# That path walked every descendant name, so the bare `req`/`webhook`/`request`
# inside a chain `_is_source_chain` had already rejected re-tainted the local,
# and the local then carried a critical finding to the sink. Each of these is a
# chain the structural rule rejects — a client member, or a call to a
# non-factory — so binding it must introduce no taint and reach the sink clean.
LOOKALIKE_BOUND_TO_LOCAL = [
    ("req.url",
     "import os\n"
     "def go(req):\n"
     "    v = req.url\n"
     '    os.system("curl " + v)\n'),
    ("webhook.url",
     "import os\n"
     "def go(webhook):\n"
     "    v = webhook.url\n"
     '    os.system("curl " + v)\n'),
    ("req.timeout",
     "import os\n"
     "def go(req):\n"
     "    v = req.timeout\n"
     '    os.system("curl " + str(v))\n'),
    ("request-called",
     "import os\n"
     "def go(request):\n"
     '    v = request("GET", "u")\n'
     '    os.system("curl " + str(v))\n'),
]


@pytest.mark.parametrize("name,source", LOOKALIKE_BOUND_TO_LOCAL)
def test_a_lookalike_bound_to_a_local_introduces_no_taint(
    tmp_path: Path, name: str, source: str
) -> None:
    """A chain the structural rule rejects must not taint through a local.

    `reads_user_input` scanned descendant names, so `req.url` bound to `v`
    re-admitted `req` by its name and made `v` a critical `CG-CMD-EXEC` finding
    at the sink — a strict regression on `v = req.url`, which reported at all
    only after the name scan replaced the substring era. The introduction rule
    now asks `_is_source_chain` of the expression, so the binding is clean.
    """
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert [f.rule_id for f in findings] == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_req_url_bound_to_a_local_is_specifically_not_critical(tmp_path: Path) -> None:
    """The named regression, pinned at its severity.

    `v = req.url` reported `high` before the fix round and `critical` after it,
    a strict escalation on a false positive. It must now report nothing; in no
    case may it be `critical`.
    """
    source = (
        "import os\n"
        "def go(req):\n"
        "    v = req.url\n"
        '    os.system("curl " + v)\n'
    )
    _nodes, _edges, findings = _analyze(tmp_path, source)
    assert findings == [], [f.rule_id for f in findings]
    assert all(f.severity != "critical" for f in findings)


# --- The source cross-product (M10) ------------------------------------------
# `test_a_framework_read_is_still_a_source` writes every FRAMEWORK_READS shape
# *inline* at the sink argument, where `_has_tainted_name` -> `user_input_nodes`
# answers it. `test_taint_is_found_in_every_binding_form_not_only_assignment`
# binds to a local, but every one of its shapes is `request.*`, answered by the
# bare-`request` name. Neither exercises a *non-request-rooted* source bound to
# a local, which is the only path through `reads_user_input`'s `_is_source_chain`
# branch (provenance.py). Deleting that branch presents as a clean scan while
# silently dropping the WSGI/ASGI/Lambda/cgi and framework-factory sources.

FRAMEWORK_READS_BOUND_TO_LOCAL = [
    # Protocol-level containers read by subscript at a request field.
    ("wsgi-environ",
     "def app(environ, start_response):\n"
     "    q = environ['QUERY_STRING']\n"
     "    return cursor.execute('select ' + q)\n"),
    ("asgi-scope",
     "async def app(scope, receive, send):\n"
     "    q = scope['query_string']\n"
     "    return cursor.execute('select ' + q)\n"),
    ("lambda-event",
     "def handler(event, context):\n"
     "    q = event['body']\n"
     "    return cursor.execute('select ' + q)\n"),
    ("os-environ-http",
     "import os\n"
     "def go():\n"
     "    q = os.environ['HTTP_USER_AGENT']\n"
     "    return cursor.execute('select ' + q)\n"),
    # A member distinctive enough to name an inbound API on its own.
    ("query-params-member",
     "def go(obj):\n"
     "    q = obj.query_params.get('u')\n"
     "    return cursor.execute('select ' + q)\n"),
    ("cgi-getvalue",
     "import cgi\n"
     "def go(form):\n"
     "    q = form.getvalue('u')\n"
     "    return cursor.execute('select ' + q)\n"),
    # A source factory spelled the way the framework spells it.
    ("fastapi-query-factory",
     "from fastapi import Query\n"
     "def go():\n"
     "    q = Query(None)\n"
     "    return cursor.execute('select ' + q)\n"),
]


@pytest.mark.parametrize(
    "name,source",
    FRAMEWORK_READS_BOUND_TO_LOCAL,
    ids=[n for n, _ in FRAMEWORK_READS_BOUND_TO_LOCAL],
)
def test_a_framework_read_bound_to_a_local_still_taints(tmp_path: Path, name: str, source: str):
    """A genuine, non-request-rooted source bound to a local must still reach the sink."""
    _nodes, edges, findings = _analyze(tmp_path, source)
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges)


# --- A bare request bound to a local reaches a PATH sink (M2, end to end) -----
# The unit form lives in `test_predicates.py`; here the whole pipeline is
# exercised, so the rule id, its severity and the surviving REACHES_SINK edge
# are pinned rather than a bare non-empty count. Dropping the `origin_carriers`
# guard in `_assess_path` clears the finding.

REQUEST_BOUND_PATH = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.get('/f')\n"
    "def h():\n"
    "    r = request\n"
    "    return open(r).read()\n"
)


def test_a_bare_request_bound_to_a_local_reaches_a_path_sink(tmp_path: Path):
    _nodes, edges, findings = _analyze(tmp_path, REQUEST_BOUND_PATH)
    assert [f.rule_id for f in findings] == ["CG-PATH-TRAVERSAL"], [f.rule_id for f in findings]
    assert findings[0].severity == "high"
    assert any(e.kind == "REACHES_SINK" for e in edges)


def test_os_system_command_injection_is_critical(tmp_path: Path):
    """Nothing else asserts the severity of a CG-CMD-EXEC finding.

    `os.system` runs a shell inherently, so a tainted argument is a confirmed
    critical command injection. A mutation downgrading the sink to `medium`
    passed the whole suite.
    """
    source = (
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/r')\n"
        "def run(cmd: str):\n"
        "    os.system('echo ' + cmd)\n"
    )
    _nodes, _edges, findings = _analyze(tmp_path, source)
    assert [f.rule_id for f in findings] == ["CG-CMD-EXEC"], [f.rule_id for f in findings]
    assert findings[0].severity == "critical", findings[0].severity
