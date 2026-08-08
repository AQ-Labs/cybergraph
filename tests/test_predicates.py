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


# F2 (Important): shell=True with tainted argv is a confirmed injection —
# checked ahead of the non-constant-argv0 fallback below.
#
# F3's original fix narrowed a flag-based fallback by inspecting argv[1].
# Round 3 (C2/C3) deleted flag inspection entirely — a flag byte has no
# meaning independent of the program (`-i` is "load a library" to gawk and
# "an input file" to ffmpeg) — so shell involvement for a non-constant argv[0]
# is now always UNKNOWN when any element is tainted, never SAFE. The six
# shapes below that F3 had rescued to SAFE (`sys.executable`, `shutil.which`,
# `self.git`, a bare global, `os.environ[...]`, `self.ffmpeg`) abstain again;
# see `test_non_constant_argv0_with_tainted_argv_is_unknown`.


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
    "body,params",
    [
        ('subprocess.run([sys.executable, "-m", "pytest", test_id])', "test_id"),
        ('subprocess.run([shutil.which("git"), "show", rev])', "rev"),
        ('subprocess.run([self.git, "show", rev])', "rev"),
        ('subprocess.run([GIT, "show", rev])', "rev"),
        ('subprocess.run([os.environ["GIT"], "show", rev])', "rev"),
        ('subprocess.run([self.ffmpeg, "-i", media, "-y", out])', "media, out"),
        ("subprocess.run([SHELL, '-c', cmd])", "cmd"),
        ("subprocess.run([self.shell, '-c', cmd])", "cmd"),
        ("flag = get_flag()\n    subprocess.run([shell_path, flag, cmd])", "cmd"),
    ],
)
def test_non_constant_argv0_with_tainted_argv_is_unknown(body, params):
    """argv[0] is not a literal, so its identity can't be resolved either way."""
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
        == VERDICT_SAFE
    )
    assert (
        _assess(
            'render_template_string("<p>{{ n }}</p>", n=user_input)',
            "render_template_string",
            params="user_input",
        )
        == VERDICT_SAFE
    )


def test_template_direct_taint_is_unsafe():
    """The canonical SSTI shape: the whole template argument is tainted."""
    assert (
        _assess("render_template_string(user_input)", "render_template_string",
                 params="user_input")
        == VERDICT_UNSAFE
    )


# --- Fix round 2 ---

# N2 (Important): an untainted template is safe regardless of how opaque its
# construction is, mirroring `_assess_sql`'s short-circuit order — checking
# taint before construction, not after.


@pytest.mark.parametrize(
    "body,expected",
    [
        ("render_template_string(TEMPLATE, name=user_input)", VERDICT_SAFE),
        ("render_template_string(load_tpl(), name=uid)", VERDICT_SAFE),
        ("render_template_string(self.template, name=uid)", VERDICT_SAFE),
        ('render_template_string("<p>" + user_input + "</p>")', VERDICT_UNSAFE),
    ],
)
def test_template_untainted_opaque_construction_is_safe(body, expected):
    assert _assess(body, "render_template_string", params="user_input, uid") == expected


# N1 (Critical, round 2): a flag-based fallback must prove safety by
# membership in a known-safe flag set, not by absence from a known-shell set —
# an incomplete danger set silently clears every flag it forgot.
#
# Round 3 (C2/C3) deleted flag inspection altogether: none of these shapes use
# a literal argv[0] (they're all a variable, attribute, or bare global that
# *might* hold a shell name), so under the current rule they abstain simply
# because argv[0] isn't a constant — the same outcome, for a different and
# now-simpler reason.


@pytest.mark.parametrize(
    "body,params",
    [
        ("shell = get_shell()\n    subprocess.run([shell, '-lc', cmd])", "cmd"),
        ("subprocess.run([self.shell, '-lc', cmd])", "cmd"),
        ("subprocess.run([BASH, '-xc', cmd])", "cmd"),
        ("subprocess.run([cmd_exe, '/C', user_cmd])", "user_cmd"),
        ("subprocess.run([COMSPEC, '/K', user_cmd])", "user_cmd"),
        ("subprocess.run([ps, '-command', user_cmd])", "user_cmd"),
        ("subprocess.run([ps, '-NoProfile', user_cmd])", "user_cmd"),
        ("subprocess.run([sh, '-ic', cmd])", "cmd"),
        ("subprocess.run([sh, '--command', cmd])", "cmd"),
        ("subprocess.run([interp, '-e', cmd])", "cmd"),
    ],
)
def test_unlisted_shell_flags_are_not_proven_safe(body, params):
    assert _assess(body, "run", params=params) == VERDICT_UNKNOWN


# --- Fix round 3 ---

# C2 + C3 (Critical): shell/interpreter involvement for a list argv is decided
# from argv[0]'s identity alone — never from a flag byte, which has no
# meaning independent of the program running it.


@pytest.mark.parametrize(
    "body,params",
    [
        # Controls: already correctly unsafe before round 3.
        ('subprocess.run(["cmd", "/c", cmd])', "cmd"),
        ('subprocess.run(["sh", "-c", cmd])', "cmd"),
        # Unlisted/case-varied shell flags, now caught because only argv[0]'s
        # identity matters, not the flag.
        ("subprocess.run(['bash', '-lc', cmd])", "cmd"),
        ("subprocess.run(['sh', '-xc', cmd])", "cmd"),
        ("subprocess.run(['sh', '-ic', cmd])", "cmd"),
        ("subprocess.run(['zsh', '-lc', cmd])", "cmd"),
        ("subprocess.run(['cmd.exe', '/C', cmd])", "cmd"),
        ("subprocess.run(['cmd', '/K', cmd])", "cmd"),
        ("subprocess.run(['powershell', '-command', cmd])", "cmd"),
        # Basename folding.
        ("subprocess.run(['/bin/bash', '-lc', cmd])", "cmd"),
        # Case and .exe-suffix folding.
        ("subprocess.run(['CMD.EXE', '/c', cmd])", "cmd"),
        # Interpreters that take inline code — a flag was never the tell.
        ("subprocess.run(['python', '-c', cmd])", "cmd"),
        ("subprocess.run(['python', '-m', cmd])", "cmd"),
        ("subprocess.run(['awk', '-f', cmd])", "cmd"),
        ("subprocess.run(['awk', '--file', cmd])", "cmd"),
        ("subprocess.run(['gawk', '-i', cmd])", "cmd"),
        ("subprocess.run(['ssh', '-o', cmd])", "cmd"),
    ],
)
def test_shell_or_interpreter_identity_is_unsafe_regardless_of_flag(body, params):
    assert _assess(body, "run", params=params) == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,params",
    [
        ('subprocess.run(["git", "show", rev])', "rev"),
        ('subprocess.run(["git", "log", "--", path])', "path"),
    ],
)
def test_constant_non_shell_argv0_stays_safe(body, params):
    assert _assess(body, "run", params=params) == VERDICT_SAFE


# C1 (Critical, regression from round 2): a template mirrors `_assess_sql`
# only for its untainted short-circuit. Any tainted template argument is
# unsafe outright — there is no bound-parameter-equivalent safe mechanism for
# an OPAQUE-but-tainted template the way there is for SQL.


@pytest.mark.parametrize(
    "body,expected",
    [
        ("render_template_string(user_input)", VERDICT_UNSAFE),
        ("render_template_string(source=user_input)", VERDICT_UNSAFE),
        ("render_template_string(template=user_input)", VERDICT_UNSAFE),
        ('render_template_string(user_input, name="x")', VERDICT_UNSAFE),
        ("render_template_string(user_input.strip())", VERDICT_UNSAFE),
        ("render_template_string(TEMPLATES[user_input])", VERDICT_UNSAFE),
        ("render_template_string(get_tpl(uid))", VERDICT_UNSAFE),
    ],
)
def test_template_opaque_taint_is_unsafe_not_unknown(body, expected):
    assert (
        _assess(body, "render_template_string", params="user_input, uid")
        == expected
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
