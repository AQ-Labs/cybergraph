import ast

import pytest

from cybergraph.analysis.provenance import snapshot_call_sites
from cybergraph.security.predicates import (
    VERDICT_SAFE,
    VERDICT_UNKNOWN,
    VERDICT_UNSAFE,
    assess_call,
)
from cybergraph.security.sinks import lookup_sink


def _assess(body: str, callee: str, params: str = "uid"):
    src = f"def f({params}):\n    {body}\n"
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    tainted = {a.arg: f"input:{a.arg}" for a in fn.args.args}
    states = snapshot_call_sites(fn, tainted)
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    sink = lookup_sink(ast.unparse(call.func), "python")
    assert sink is not None, ast.unparse(call.func)
    return assess_call(sink, call, states[id(call)])


@pytest.mark.parametrize(
    "body,expected",
    [
        ('cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))', VERDICT_SAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = :id", {"id": uid})', VERDICT_SAFE),
        ('cursor.execute("SELECT 1")', VERDICT_SAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = " + uid)', VERDICT_UNSAFE),
        ('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")', VERDICT_UNSAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = %s" % uid)', VERDICT_UNSAFE),
        ("cursor.execute(build_query(uid))", VERDICT_UNKNOWN),
    ],
)
def test_sql(body, expected):
    assert _assess(body, "execute") == expected


def test_sql_composed_but_clean_is_safe():
    """Dynamic construction with no user data in the query text is not injection."""
    assert _assess('cursor.execute(f"SELECT * FROM t ORDER BY id")', "execute") == VERDICT_SAFE


@pytest.mark.parametrize(
    "body,expected",
    [
        ('subprocess.run(["git", "show", rev], shell=False)', VERDICT_SAFE),
        ('subprocess.run(["git", "show", rev])', VERDICT_SAFE),
        ('subprocess.run(["git", "show"])', VERDICT_SAFE),
        ('subprocess.run("git show " + rev, shell=True)', VERDICT_UNSAFE),
        ("subprocess.run(rev, shell=True)", VERDICT_UNSAFE),
        ('subprocess.run(["sh", "-c", rev])', VERDICT_UNSAFE),
        ('subprocess.run(["bash", "-c", rev])', VERDICT_UNSAFE),
        ("subprocess.run([rev, '--version'])", VERDICT_UNSAFE),
        ('subprocess.run(f"git show {rev}")', VERDICT_UNKNOWN),
    ],
)
def test_command(body, expected):
    assert _assess(body, "run", params="rev") == expected


def test_os_system_always_involves_a_shell():
    assert _assess('os.system("echo " + rev)', "system", params="rev") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,expected",
    [
        ("open(name)", VERDICT_UNSAFE),
        ('open("config.ini")', VERDICT_SAFE),
        ("open(os.path.basename(name))", VERDICT_SAFE),
        ("open(safe_join(ROOT, name))", VERDICT_SAFE),
        ("open(os.path.normpath(name))", VERDICT_UNKNOWN),
        ("open(os.path.realpath(name))", VERDICT_UNKNOWN),
        ("open(os.path.abspath(name))", VERDICT_UNKNOWN),
    ],
)
def test_path(body, expected):
    assert _assess(body, "open", params="name") == expected


def test_code_execution():
    assert _assess("eval(src)", "eval", params="src") == VERDICT_UNSAFE
    assert _assess('eval("1+1")', "eval", params="src") == VERDICT_SAFE


# --- Correction A: keyword arguments must be resolved, not treated as absent ---


@pytest.mark.parametrize(
    "body,expected",
    [
        ('cursor.execute(sql="SELECT * FROM t WHERE id = " + uid)', VERDICT_UNSAFE),
        ('cursor.execute(query="SELECT * FROM t WHERE id = " + uid)', VERDICT_UNSAFE),
        ('cursor.execute(statement="SELECT * FROM t WHERE id = " + uid)', VERDICT_UNSAFE),
    ],
)
def test_sql_keyword_argument_is_resolved(body, expected):
    assert _assess(body, "execute") == expected


def test_command_keyword_argument_is_resolved():
    assert _assess("subprocess.run(args=rev, shell=True)", "run", params="rev") == VERDICT_UNSAFE


def test_path_keyword_argument_is_resolved():
    assert _assess("open(file=name)", "open", params="name") == VERDICT_UNSAFE


def test_sql_no_locatable_argument_is_unknown():
    """Arguments that arrive under an unrecognised keyword must not read as SAFE."""
    assert _assess("cursor.execute(**kwargs)", "execute", params="uid, **kwargs") == VERDICT_UNKNOWN


# --- Correction B: starred, tainted argv elements are argument injection ---


def test_starred_tainted_argv_is_unknown():
    assert (
        _assess("subprocess.run(['git', *extra_args])", "run", params="extra_args")
        == VERDICT_UNKNOWN
    )


# --- Correction C: a non-constant argv[0] with tainted argv must not read as SAFE ---


def test_variable_shell_path_with_tainted_argv_is_unknown():
    """argv[0] is a variable, not a literal, so we cannot rule out it being a shell."""
    body = (
        "shell_path = get_shell()\n"
        '    subprocess.run([shell_path, "-c", rev])'
    )
    assert _assess(body, "run", params="rev") == VERDICT_UNKNOWN
