import ast

import pytest

from cybergraph.analysis.provenance import snapshot_call_sites
from cybergraph.security.predicates import (
    VERDICT_SAFE,
    VERDICT_UNKNOWN,
    VERDICT_UNSAFE,
    _find_argument,
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


# --- Fix round 1 ---

# F1 (Critical): a confining call must exonerate only the tainted names it
# actually wraps, not the whole expression the moment any confining call
# appears anywhere in it.


@pytest.mark.parametrize(
    "body,params,expected",
    [
        (
            'open(user_dir + "/" + os.path.basename(name))',
            "user_dir, name",
            VERDICT_UNSAFE,
        ),
        (
            "open(os.path.join(name, os.path.basename(other)))",
            "name, other",
            VERDICT_UNSAFE,
        ),
        (
            'open(base + os.path.basename("x"))',
            "base",
            VERDICT_UNSAFE,
        ),
    ],
)
def test_path_confinement_is_scoped_to_the_confining_calls_own_arguments(
    body, params, expected
):
    assert _assess(body, "open", params=params) == expected


# F2 + F3 (Important): shell=True with tainted argv is a confirmed injection —
# checked ahead of the argv[0]-shape fallback — and the fallback itself is
# narrowed by argv[1] so a clearly-non-shell argv[1] does not trigger it.


@pytest.mark.parametrize(
    "body,callee,params",
    [
        ("tool = get_tool()\n    subprocess.run([tool, cmd], shell=True)", "run", "cmd"),
        ("subprocess.run([TOOL, cmd], shell=True)", "run", "cmd"),
        ("subprocess.run([self.tool, cmd], shell=True)", "run", "cmd"),
        ('subprocess.Popen([shutil.which("sh"), cmd], shell=True)', "Popen", "cmd"),
        (
            "tool = get_tool()\n    subprocess.run(args=[tool, cmd], shell=True)",
            "run",
            "cmd",
        ),
        ("tool = get_tool()\n    os.system([tool, cmd])", "system", "cmd"),
    ],
)
def test_shell_true_with_tainted_argv_is_unsafe_not_unknown(body, callee, params):
    assert _assess(body, callee, params=params) == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,params,expected",
    [
        (
            'subprocess.run([sys.executable, "-m", "pytest", test_id])',
            "test_id",
            VERDICT_SAFE,
        ),
        ('subprocess.run([shutil.which("git"), "show", rev])', "rev", VERDICT_SAFE),
        ('subprocess.run([self.git, "show", rev])', "rev", VERDICT_SAFE),
        ('subprocess.run([GIT, "show", rev])', "rev", VERDICT_SAFE),
        ('subprocess.run([os.environ["GIT"], "show", rev])', "rev", VERDICT_SAFE),
        (
            'subprocess.run([self.ffmpeg, "-i", media, "-y", out])',
            "media, out",
            VERDICT_SAFE,
        ),
    ],
)
def test_argv0_shape_fallback_does_not_fire_when_argv1_rules_it_out(body, params, expected):
    assert _assess(body, "run", params=params) == expected


@pytest.mark.parametrize(
    "body,params",
    [
        ("subprocess.run([SHELL, '-c', cmd])", "cmd"),
        ("subprocess.run([self.shell, '-c', cmd])", "cmd"),
        ("flag = get_flag()\n    subprocess.run([shell_path, flag, cmd])", "cmd"),
    ],
)
def test_argv0_shape_fallback_still_fires_when_argv1_does_not_rule_it_out(body, params):
    assert _assess(body, "run", params=params) == VERDICT_UNKNOWN


# F4 (Important): template context values are the safe mechanism, mirroring
# SQL bind parameters — only the template text itself is the injection vector.


def test_template_context_values_are_not_the_injection_vector():
    assert (
        _assess(
            "render_template_string(TEMPLATE, name=user_input)",
            "render_template_string",
            params="user_input",
        )
        == VERDICT_UNKNOWN
    )
    assert (
        _assess(
            'render_template_string("<p>{{ n }}</p>", n=user_input)',
            "render_template_string",
            params="user_input",
        )
        == VERDICT_SAFE
    )


# F5 (Minor): a call missing from the snapshot mapping must read as unknown,
# never safe — the natural `states.get(id(call), CallState())` a future
# caller might write must not silently degrade to "clean".


@pytest.mark.parametrize(
    "body,callee,params",
    [
        ('cursor.execute("S " + uid)', "execute", "uid"),
        ("os.system(uid)", "system", "uid"),
        ('subprocess.run(["sh", "-c", uid])', "run", "uid"),
    ],
)
def test_missing_call_state_is_unknown_not_safe(body, callee, params):
    src = f"def f({params}):\n    {body}\n"
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    sink = lookup_sink(ast.unparse(call.func), "python")
    assert assess_call(sink, call, None) == VERDICT_UNKNOWN


# F6 (Minor): an unrecognised vuln class must not raise KeyError out of the
# keyword-name lookup.


def test_find_argument_unknown_vuln_class_returns_none():
    call = ast.parse("f(x=1)", mode="eval").body
    assert _find_argument(call, "not-a-real-class") is None
