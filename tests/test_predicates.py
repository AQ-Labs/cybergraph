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


# The same "an argument that cannot be located is unknown, never safe" invariant,
# for the three classes that had it only for SQL. Each asserts the resolved
# `sink.vuln_class` as well as the verdict, so the case cannot pass by
# `lookup_sink` returning `None` (which would skip dispatch entirely).


@pytest.mark.parametrize(
    "body,params,callee,vuln_class",
    [
        ("subprocess.run(**opts)", "cmd, **opts", "run", "command"),
        ("subprocess.run(cwd=d, shell=True)", "d", "run", "command"),
        ("os.system(**opts)", "cmd, **opts", "system", "command"),
        ("open(**opts)", "name, **opts", "open", "path"),
        ("render_template_string(**ctx)", "u, **ctx", "render_template_string", "template"),
    ],
)
def test_command_path_template_unlocatable_argument_is_unknown(body, params, callee, vuln_class):
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
    assert sink.vuln_class == vuln_class, sink.vuln_class
    assert assess_call(sink, call, states[id(call)]) == VERDICT_UNKNOWN


# The `_assess_path` origin/confinement guard: a producer confines a name only
# if it had a carrier to confine and confined all of it. Dropping the
# `origin_carriers and` guard makes `all(...)` over an empty set vacuously true,
# so a bare request object bound to a local (`r = request; open(r)`) -- whose
# origin has no *named* taint inside it -- reads as "everything confined" and
# clears outright. Its own comment calls dropping the guard "the whole bug
# inverted". `a = sys.argv` is the calibration case the mutation leaves unsafe
# (its origin has a chain carrier), so it is deliberately not asserted here.


@pytest.mark.parametrize(
    "body",
    [
        "r = request\n    open(r)",
        'r = request\n    open("/data/" + r)',
        "r = req\n    open(r)",
        "a = argv\n    open(a)",
    ],
)
def test_a_bare_request_bound_to_a_local_is_not_confined(body):
    assert _assess(body, "open", params="unused") == VERDICT_UNSAFE


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
        # Round 5 moved `awk -f`, `awk --file`, `gawk -i` and `ssh -o` out of
        # this test: those are another program's flags taking code, which is the
        # argument/config-injection family now out of scope. They are kept as
        # scope-boundary tests in
        # `test_argument_and_config_injection_is_out_of_scope`.
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
    # Without this the three cases are indistinguishable — `state is None`
    # returns before dispatch, so the test would pass with every predicate
    # deleted, or with `lookup_sink` returning None for all three.
    assert sink is not None, ast.unparse(call.func)
    assert sink.vuln_class in {"sql", "command"}
    assert assess_call(sink, call, None) == VERDICT_UNKNOWN


# F6 (Minor): an unrecognised vuln class must not raise KeyError out of the
# keyword-name lookup.


def test_find_argument_unknown_vuln_class_returns_none():
    call = ast.parse("f(x=1)", mode="eval").body
    assert _find_argument(call, "not-a-real-class") is None


# --- Fix round 4 ---

# N-A + N-B (Critical): a program determines which argv positions it treats as
# code, and the program is not always at position 0. Identity without position
# calls every ordinary interpreter invocation critical; position without
# identity misses every shell sitting one slot right of a wrapper.


@pytest.mark.parametrize(
    "body,params",
    [
        ('["python", "manage.py", "migrate", app]', "app"),
        ('["python", "script.py", arg]', "arg"),
        ('["python3", "-m", "pip", "install", pkg]', "pkg"),
        ('["python", "-m", "pytest", test_id]', "test_id"),
        ('["node", "build.js", target]', "target"),
        ('["perl", "fix.pl", filename]', "filename"),
        ('["ruby", "app.rb", "-p", port]', "port"),
        ('["awk", "{print $2}", user_file]', "user_file"),
        ('["awk", "-F,", "{print $1}", csv]', "csv"),
        ('["busybox", "ls", d]', "d"),
        ('["bash", "deploy.sh", version]', "version"),
        ('["sh", "./configure", "--prefix=" + prefix]', "prefix"),
        ('["pwsh", "-File", "build.ps1", target]', "target"),
        ('["powershell", "-File", script_path]', "script_path"),
        ('["python", "-u", worker_script]', "worker_script"),
        ('["mawk", "-f", "prog.awk", data]', "data"),
        # The same class, read off the program table rather than the report.
        ('["java", "-jar", jar_path]', "jar_path"),
        ('["java", "-cp", classpath, "Main", arg]', "classpath, arg"),
        ('["Rscript", "report.R", input_csv]', "input_csv"),
        ('["sed", "-e", "s/a/b/", data_file]', "data_file"),
        ('["tar", "-cf", archive, folder]', "archive, folder"),
        ('["scp", src, "host:/tmp/"]', "src"),
        ('["rsync", "-a", src, dest]', "src, dest"),
        ('["git", "show", rev]', "rev"),
        ('["python", "-m", "pip", "download", pkg, "-d", "/tmp"]', "pkg"),
    ],
)
def test_taint_outside_the_programs_code_positions_is_safe(body, params):
    """An interpreter running a script is not an interpreter running user data.

    The original N-A false positives, kept as the regression record. Since round
    5 they are safe for two different reasons: the shells and interpreters in
    `_CODE_RUNNERS` reach it through rule 5, with every flag accounted for, and
    the rest (`awk`, `sed`, `tar`, `scp`, `rsync`, `git`, `java`, `Rscript`,
    `busybox`) through rule 8, naming no runner at all.
    """
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_SAFE


@pytest.mark.parametrize(
    "body",
    [
        '["sh", "-c", cmd]', '["bash", "-lc", cmd]', '["zsh", "-c", cmd]',
        '["dash", "-c", cmd]', '["ksh", "-c", cmd]', '["ash", "-c", cmd]',
        '["fish", "-c", cmd]', '["csh", "-c", cmd]', '["tcsh", "-c", cmd]',
        '["bash", "-eic", cmd]', '["bash", "-xc", cmd]', '["sh", "-ic", cmd]',
        '["cmd", "/c", cmd]', '["cmd.exe", "/K", cmd]', '["command.com", "/c", cmd]',
        '["powershell", "-Command", cmd]', '["powershell", "-Comm", cmd]',
        '["pwsh", "-enc", cmd]', '["powershell", "-command", cmd]',
        '["python", "-c", cmd]', '["python3", "-c", cmd]', '["python2", "-c", cmd]',
        '["ipython", "-c", cmd]', '["python", "-m", cmd]',
        '["perl", "-e", cmd]', '["perl", "-E", cmd]', '["perl", "-M" + cmd]',
        '["perl", "-pe", cmd]', '["ruby", "-e", cmd]',
        '["node", "-e", cmd]', '["node", "--eval", cmd]', '["node", "-p", cmd]',
        '["node", "--print", cmd]', '["node", "-r", cmd]',
        '["php", "-r", cmd]', '["php", "-B", cmd]', '["php", "-R", cmd]',
        '["php", "-F", cmd]',
        # Basename, case and suffix folding on argv[0].
        '["/bin/bash", "-c", cmd]', '["/usr/local/bin/python3", "-c", cmd]',
        '["CMD.EXE", "/c", cmd]', '["BASH", "-c", cmd]',
        # `cmd /c` and `-Command` take the rest of the command line.
        '["cmd", "/c", "dir", cmd]', '["powershell", "-Command", "ls", cmd]',
        # Code bundled into the flag's own token.
        '["python", "-c" + cmd]', '["bash", "-c" + cmd]',
    ],
)
def test_taint_in_a_runners_code_position_is_unsafe(body):
    """Rule 4: a runner in `_CODE_RUNNERS`, handed user data as code."""
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,expected",
    [
        # `-m` names a module to run: a tainted module name is code selection,
        # a tainted argument to an already-named module is not.
        ('["python", "-m", "pytest", cmd]', VERDICT_SAFE),
        ('["python", "-m", cmd]', VERDICT_UNSAFE),
        # `-File` takes a path; `-Command` takes code.
        ('["powershell", "-File", cmd]', VERDICT_SAFE),
        ('["powershell", "-Command", cmd]', VERDICT_UNSAFE),
        # `-p` evaluates for `node` and is loop mode for `ruby`, which is why
        # these two cannot share one entry in the runner table.
        ('["node", "-p", cmd]', VERDICT_UNSAFE),
        ('["ruby", "app.rb", "-p", cmd]', VERDICT_SAFE),
        # `-f` parses one named file for php; `-r` runs a snippet.
        ('["php", "-f", "x.php", cmd]', VERDICT_SAFE),
        ('["php", "-r", cmd]', VERDICT_UNSAFE),
    ],
)
def test_the_same_flag_letter_means_different_things_per_runner(body, expected):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == expected


def test_starred_argv_in_a_code_position_is_unsafe_not_unknown():
    """`["bash", "-c", *args]` is provable; `["git", *args]` is not."""
    assert (
        _assess('subprocess.run(["bash", "-c", *args])', "run", params="args")
        == VERDICT_UNSAFE
    )
    assert (
        _assess('subprocess.run(["git", *args])', "run", params="args") == VERDICT_UNKNOWN
    )


# Rule 7, the generic wrapper rule: a wrapper *name* list has the wrong polarity,
# because a wrapper nobody listed would clear `["newwrapper", "bash", "-c", t]`.
# Looking downstream for the runner instead needs no wrapper list at all, and
# covers every wrapper not yet written. These were UNSAFE before round 5; the
# shell is still found, but its own argv can no longer be read through the
# wrapper's, so the honest answer is an abstention.


@pytest.mark.parametrize(
    "body",
    [
        '["env", "bash", "-c", cmd]',
        '["/usr/bin/env", "sh", "-c", cmd]',
        '["sudo", "sh", "-c", cmd]',
        '["sudo", "-u", "www", "bash", "-c", cmd]',
        '["nohup", "bash", "-c", cmd]',
        '["timeout", "5", "sh", "-c", cmd]',
        '["timeout", "10", "bash", "-c", cmd]',
        '["nice", "sh", "-c", cmd]',
        '["setsid", "bash", "-c", cmd]',
        '["stdbuf", "-o0", "sh", "-c", cmd]',
        '["flock", "/tmp/l", "sh", "-c", cmd]',
        '["xargs", "-I{}", "sh", "-c", cmd]',
        '["docker", "run", "img", "sh", "-c", cmd]',
        '["docker", "run", "img", "bash", "-c", cmd]',
        '["docker", "exec", "c", "sh", "-c", cmd]',
        '["kubectl", "exec", "p", "--", "sh", "-c", cmd]',
        '["wsl", "bash", "-c", cmd]',
        '["podman", "run", "img", "bash", "-c", cmd]',
        '["doas", "sh", "-c", cmd]',
        '["chroot", "/jail", "sh", "-c", cmd]',
        '["unbuffer", "bash", "-c", cmd]',
        '["ionice", "-c2", "sh", "-c", cmd]',
        '["busybox", "sh", "-c", cmd]',
        # Folding still applies to the downstream name.
        '["sudo", "/bin/BASH", "-c", cmd]',
        '["env", "CMD.EXE", "/c", cmd]',
        '["nohup", "C:\\\\Windows\\\\System32\\\\cmd.exe", "/c", cmd]',
        # A wrapper nobody enumerated, which is the point of the rule.
        '["newwrapper", "bash", "-c", cmd]',
        '["torify", "sh", "-c", cmd]',
        # A runner named anywhere downstream, wrapper or not.
        '["env", "FOO=1", "python", "x.py", cmd]',
    ],
)
def test_a_runner_named_downstream_abstains(body):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_UNKNOWN


# Rule 8, the accepted scope boundary. Every shape below is the same family:
# **argument/config injection through some other program's flags**. Separating
# them from `["git", "show", rev]` needs per-program flag semantics, which three
# rounds showed cannot be encoded without a table that is wrong somewhere else.
# Out of scope for this phase, and recorded here so the gap is visible rather
# than forgotten. All of these were UNSAFE before round 5.


@pytest.mark.parametrize(
    "body",
    [
        # A program's flag that takes a program file or inline text.
        '["awk", "-f", cmd]', '["awk", "--file", cmd]', '["awk", cmd, "f.txt"]',
        '["gawk", "-i", cmd]', '["gawk", "--source", cmd]', '["mawk", "-f", cmd]',
        '["nawk", "-f", cmd]', '["sed", "-e", cmd]',
        '["find", ".", "-exec", cmd, ";"]',
        '["make", "-f", cmd]', '["cmake", "-P", cmd]',
        '["mysql", "-e", cmd]', '["mysql", "--execute", cmd]', '["psql", "-c", cmd]',
        '["nc", "-e", cmd]', '["ncat", "-e", cmd]', '["socat", "-e", cmd]',
        '["socat", cmd, "-"]',
        '["tar", "-I", cmd, "-cf", "a.tgz", "d"]',
        '["vim", "-c", cmd]', '["ex", "--eval", cmd]', '["emacs", "--eval", cmd]',
        '["ed", cmd]',
        # Interpreters outside the runner table: the same shape as `lua -e`.
        '["lua", "-e", cmd]', '["luajit", "-e", cmd]', '["deno", "eval", cmd]',
        '["bun", "-e", cmd]', '["groovy", "-e", cmd]', '["scala", "-e", cmd]',
        '["expect", "-c", cmd]', '["tclsh", "-c", cmd]', '["wish", "-c", cmd]',
        '["R", "-e", cmd]', '["Rscript", "-e", cmd]', '["osascript", "-e", cmd]',
        # Windows script hosts.
        '["wscript", cmd]', '["cscript", cmd]', '["cscript", "//nologo", cmd]',
        '["mshta", cmd]', '["rundll32", cmd]', '["regsvr32", cmd]',
        # Config injection: a setting that names a command to run.
        '["git", "-c", cmd, "fetch"]',
        '["git", "-c", "core.sshCommand=" + cmd, "fetch"]',
        '["git", "--exec-path=" + cmd, "fetch"]',
        '["ssh", "-o", cmd]', '["ssh", "-oProxyCommand=" + cmd, "host"]',
        '["scp", "-o", cmd, "a", "b"]', '["rsync", "-e", cmd, "a", "b"]',
        '["rsync", "--rsh=" + cmd, "a", "b"]',
        # `ssh`'s own operands: a tainted host is `-o` injection and a tainted
        # trailing operand is a remote command. Same family, same gap.
        '["ssh", cmd]', '["ssh", "myhost", cmd]',
        # Round 6 removed `["sudo", "-u", "www", sh, "-c", cmd]` from this list.
        # It was never this family: the shell is *visibly* present there, as a
        # `-c` with a tainted operand, and only its *name* was unreadable. Rule
        # 7b now abstains on it — see
        # `test_an_unreadable_program_before_a_code_flag_abstains`.
    ],
)
def test_argument_and_config_injection_is_out_of_scope(body):
    """Rule 8. Documented gap, not an oversight — see `_assess_list_argv`."""
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_SAFE


@pytest.mark.parametrize(
    "body,params",
    [
        # An element we cannot read, immediately left of the tainted one, might
        # be the very code flag that would make it code.
        ('["bash", flag, cmd]', "cmd"),
        ('["python", opt, cmd]', "cmd"),
        # A flag of a known runner that is not in its known-flag set: the set is
        # consulted to GRANT safety, so anything unrecognised must abstain. This
        # is what stops an incomplete table from becoming a silent miss.
        ('["bash", "--made-up-flag", cmd]', "cmd"),
        ('["python", "--made-up-flag", cmd]', "cmd"),
        ('["powershell", "-MadeUp", cmd]', "cmd"),
        ('["cmd", "/z", cmd]', "cmd"),
        # A non-constant argv[0]: its identity cannot be resolved either way.
        ('[shell_path, "-c", cmd]', "cmd"),
        ('[sys.executable, "-m", "pytest", cmd]', "cmd"),
        # A starred element of unknown width, outside a proven code position.
        ('["git", *extra]', "extra"),
    ],
)
def test_a_position_that_cannot_be_pinned_down_abstains(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_UNKNOWN


@pytest.mark.parametrize(
    "body",
    [
        # Ordinary code that names no runner anywhere: rule 8's other, benign half.
        '["git", "show", cmd]',
        '["git", "log", "--", cmd]',
        '["git", "clone", cmd, "dest"]',
        '["java", "-jar", cmd]',
        '["java", "-cp", cmd, "Main", "a"]',
        '["curl", "-sS", cmd]',
        '["ffmpeg", "-i", cmd, "out.mp4"]',
        '["docker", "build", "-t", cmd, "."]',
        '["kubectl", "get", "pod", cmd]',
        '["sudo", "systemctl", "restart", cmd]',
        '["timeout", "30", "curl", "-sS", cmd]',
        '["nohup", "./worker.sh", cmd]',
    ],
)
def test_a_command_naming_no_runner_is_safe(body):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_SAFE


# --- Fix round 6 ---

# Rule 7b. Rule 7 finds a downstream runner by *name*, so it missed the case
# where the program element is a variable while the shell is visibly present
# anyway â€” a `-c` with a tainted operand right after it. The element being
# unreadable was the only reason rule 7 came up empty, so this closes that gap
# rather than widening the rule.


@pytest.mark.parametrize(
    "body,params",
    [
        ('["sudo", "-u", "www", shell_var, "-c", cmd]', "shell_var, cmd"),
        ('["sudo", shell_var, "-c", cmd]', "shell_var, cmd"),
        ('["env", "FOO=1", interp, "-c", cmd]', "interp, cmd"),
        ('["timeout", "5", shell_var, "-lc", cmd]', "shell_var, cmd"),
        ('["nohup", shell_var, "-e", cmd]', "shell_var, cmd"),
        ('["wrapper", prog, "/c", cmd]', "prog, cmd"),
        ('["wrapper", prog, "-Command", cmd]', "prog, cmd"),
        # A `Starred` element is unreadable by the same token: the expansion
        # could be the shell's name.
        ('["sudo", *opts, "-c", cmd]', "opts, cmd"),
    ],
)
def test_an_unreadable_program_before_a_code_flag_abstains(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_UNKNOWN


# The "later index" condition is the whole reason rule 7b is narrow rather than
# a reversal of the round-5 scope decision. Every shape below has its unreadable
# element LAST, or with only non-flags after it, so the flag that would
# incriminate it is always *earlier* and rule 7b must not fire. These pin the
# ruled scope boundary: if rule 7 is ever widened to fire on a code flag
# anywhere in argv, this test fails loudly instead of the boundary moving in
# silence.


@pytest.mark.parametrize(
    "body",
    [
        # `-c` at index 1, unreadable element at index 2: the flag is earlier.
        '["git", "-c", "core.sshCommand=" + cmd, "fetch"]',
        '["git", "-c", cmd, "fetch"]',
        '["sed", "-e", cmd]',
        '["awk", "-f", cmd]',
        '["mysql", "-e", cmd]',
        '["psql", "-c", cmd]',
        '["nc", "-e", cmd]',
        '["socat", "-e", cmd]',
        '["vim", "-c", cmd]',
        # No flag anywhere after the unreadable element.
        '["ssh", "myhost", cmd]',
        '["git", "show", cmd]',
        # Ordinary commands whose own flags happen to sit before a variable, or
        # after one without being an inline-code flag.
        '["ping", "-c", "3", cmd]',
        '["git", "commit", "-m", cmd]',
        '["mkdir", "-p", cmd]',
        '["ffmpeg", "-i", cmd, "-y", "out.mp4"]',
        '["convert", cmd, "-resize", "50%", "out.png"]',
        '["find", ".", "-name", cmd, "-type", "f"]',
        '["make", "-C", cmd, "-f", "Makefile"]',
        '["tar", "-C", cmd, "-xf", "a.tar"]',
    ],
)
def test_rule_7b_does_not_widen_into_the_ruled_scope_boundary(body):
    """Firing on a code flag *anywhere* would drag all of these to abstaining."""
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_SAFE


# --- Fix round 7 ---

# R7-1 (Critical): `_CODE_RUNNERS` was keyed on exact basenames, so a
# version-suffixed interpreter named no runner at all and fell through to rule 8
# → safe. The table is consulted to prove DANGER, so a missing name reads as
# safety; the fix normalises the name rather than lengthening the list, because
# a list has to be complete to be correct and no list of interpreter names
# survives next year's release.


@pytest.mark.parametrize(
    "body",
    [
        '["python3.11", "-c", cmd]',
        '["python3.12", "-c", cmd]',
        '["python3.14", "-c", cmd]',
        '["/usr/bin/python3.11", "-c", cmd]',
        '["python3.11.exe", "-c", cmd]',
        '["python-3.11", "-c", cmd]',
        '["php8", "-r", cmd]',
        '["php8.2", "-r", cmd]',
        '["node20", "-e", cmd]',
        '["perl5", "-e", cmd]',
        '["ruby3.1", "-e", cmd]',
        '["ksh93", "-c", cmd]',
        '["mksh", "-c", cmd]',
        '["xonsh", "-c", cmd]',
        '["zsh5.9", "-c", cmd]',
        '["C:\\\\Python311\\\\python3.11.exe", "-c", cmd]',
    ],
)
def test_a_version_suffixed_runner_is_still_a_runner(body):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body",
    [
        # Rule 7 reads the downstream name through the same normalisation.
        '["env", "python3.11", "-c", cmd]',
        '["sudo", "python3.11", "-c", cmd]',
        '["timeout", "5", "php8.2", "-r", cmd]',
    ],
)
def test_a_version_suffixed_runner_named_downstream_abstains(body):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_UNKNOWN


@pytest.mark.parametrize(
    "body",
    [
        # Numeric operands must not normalise into a runner name: a bare `3`,
        # `30`, `644` or `./...` strips to nothing, not to a shell.
        '["ping", "-c", "3", cmd]',
        '["timeout", "30", "curl", "-sS", cmd]',
        '["chmod", "644", cmd]',
        '["go", "build", "-o", cmd, "./..."]',
        '["head", "-n", "20", cmd]',
    ],
)
def test_version_normalisation_does_not_invent_a_runner(body):
    assert _assess(f"subprocess.run({body})", "run", params="cmd") == VERDICT_SAFE


# R7-2 (Critical): `shell=` is consulted to prove DANGER, so a value that cannot
# be resolved must not read as "no shell". `subprocess` tests the value for
# truth, not identity, so `shell=1` and `shell="yes"` run a shell as surely as
# `shell=True` — the old `value is True` comparison read both as absent.


@pytest.mark.parametrize(
    "body,callee",
    [
        ('subprocess.run(["git", "show", cmd], shell=1)', "run"),
        ('subprocess.run(["git", "show", cmd], shell="yes")', "run"),
        ('subprocess.run("git show " + cmd, shell=1)', "run"),
        ('subprocess.run("git show " + cmd, shell=2)', "run"),
        ('subprocess.Popen(["git", "show", cmd], shell=1)', "Popen"),
        ('subprocess.check_output(["git", "show", cmd], shell=1)', "check_output"),
    ],
)
def test_a_truthy_non_bool_shell_keyword_is_a_shell(body, callee):
    assert _assess(body, callee, params="cmd") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,params",
    [
        # A name, an attribute, a call or a comparison: unreadable, so the shell
        # status is unknown and the call cannot be cleared.
        ('subprocess.run(["git", "show", cmd], shell=use_shell)', "cmd"),
        ('subprocess.run(["git", "show", cmd], shell=self.use_shell)', "cmd"),
        ('subprocess.run(["git", "show", cmd], shell=bool(x))', "cmd"),
        ('subprocess.run(["git", "show", cmd], shell=os.name == "nt")', "cmd"),
        # `**kwargs` may carry `shell=True`, so its absence proves nothing.
        ('subprocess.run(["git", "show", cmd], **opts)', "cmd, **opts"),
        ('subprocess.run(["git", "show", cmd], check=True, **opts)', "cmd, **opts"),
        # An unresolved shell status must not clear a rule-5 safe either.
        ('subprocess.run(["python", "-m", "pytest", cmd], shell=use_shell)', "cmd"),
    ],
)
def test_an_unresolvable_shell_keyword_is_unknown_not_absent(body, params):
    assert _assess(body, "run", params=params) == VERDICT_UNKNOWN


@pytest.mark.parametrize(
    "body,expected",
    [
        # A falsey constant really is "no shell", and still clears.
        ('subprocess.run(["git", "show", cmd], shell=False)', VERDICT_SAFE),
        ('subprocess.run(["git", "show", cmd], shell=0)', VERDICT_SAFE),
        ('subprocess.run(["git", "show", cmd], shell=None)', VERDICT_SAFE),
        ('subprocess.run(["git", "show", cmd], shell="")', VERDICT_SAFE),
        # And an unresolved shell status never demotes a confirmed injection.
        ('subprocess.run(["bash", "-c", cmd], shell=use_shell)', VERDICT_UNSAFE),
        ('subprocess.run(["bash", "-c", cmd], **opts)', VERDICT_UNSAFE),
    ],
)
def test_a_falsey_shell_keyword_still_clears(body, expected):
    assert _assess(body, "run", params="cmd, **opts") == expected


# R7-3 (Critical): the unread-neighbour guard was scoped to the *immediate* left
# neighbour, on the reasoning that "a code flag consumes exactly one element".
# That is false for the four `takes_rest=True` runners, where the flag claims
# everything after it — `["cmd", flag, "dir", <tainted>]` is `cmd /c dir
# <tainted>` when `flag` holds `"/c"`, and `x & calc` executes.


@pytest.mark.parametrize(
    "body,params",
    [
        ('["cmd", flag, "dir", cmd]', "cmd"),
        ('["cmd", flag, "/q", cmd]', "cmd"),
        ('["cmd", *opts, "/q", cmd]', "cmd"),
        ('["cmd.exe", opt, "/q", cmd]', "cmd"),
        ('["powershell", opt, "-NoProfile", cmd]', "cmd"),
        ('["pwsh", opt, "-NoLogo", cmd]', "cmd"),
        ('["command.com", opt, "/q", cmd]', "cmd"),
        # Three readable elements deep, still inside a possible consumed region.
        ('["cmd", flag, "/q", "dir", cmd]', "cmd"),
        # The control that already worked: the unreadable element adjacent.
        ('["cmd", flag, cmd]', "cmd"),
    ],
)
def test_an_unreadable_element_before_a_takes_rest_taint_abstains(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_UNKNOWN


@pytest.mark.parametrize(
    "body,params",
    [
        # Every element left of the tainted one is readable, so nothing could
        # have turned it into code — the guard must not fire on these.
        ('["powershell", "-File", script]', "script"),
        ('["pwsh", "-File", "build.ps1", target]', "target"),
        ('["cmd", "/q", "/d", name]', "name"),
        # A single-operand runner keeps the narrower immediate-left scoping:
        # `flag` cannot reach past `x`.
        ('["bash", flag, "x.sh", arg]', "arg"),
        ('["python", opt, "x.py", arg]', "arg"),
    ],
)
def test_the_takes_rest_widening_does_not_reach_readable_argv(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_SAFE


# R7-4 (Critical): the unreadable-width guard was computed over *tainted* indices
# only, so an untainted `*opts` of unknown width and unknown contents blocked
# neither rule 5 nor rule 8. `opts = ["-u", "www", "bash", "-c"]` makes
# `["sudo", *opts, <tainted>]` an arbitrary command at runtime, and moving the
# `-c` inside the starred region defeats rule 7b. Position gives no guarantee
# either — an expansion can be empty or hold twenty elements — so this is not
# narrowed to "starred before the taint".


@pytest.mark.parametrize(
    "body,params",
    [
        # The starred element is UNTAINTED; only the trailing operand is tainted.
        ('["sudo", *opts, cmd]', "cmd"),
        ('["git", *opts, cmd]', "cmd"),
        ('["ssh", *opts, cmd]', "cmd"),
        ('["env", *opts, cmd]', "cmd"),
        ('["cmd", *opts, "/q", cmd]', "cmd"),
        # Rule 5's side of it: a known runner whose argv width cannot be read.
        ('["bash", *opts, "-i", cmd]', "cmd"),
        ('["python", *opts, "x.py", cmd]', "cmd"),
        ('["powershell", *opts, "-NoLogo", cmd]', "cmd"),
        # A starred element *after* the taint bounds nothing either.
        ('["git", "show", cmd, *opts]', "cmd"),
        ('["sudo", cmd, *opts]', "cmd"),
        # And the already-correct tainted-starred cases keep abstaining.
        ('["git", *extra]', "extra"),
        ('["sudo", *extra, "-c", cmd]', "extra, cmd"),
    ],
)
def test_an_untainted_starred_element_blocks_a_clearance(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_UNKNOWN


def test_a_starred_element_in_a_proven_code_position_is_still_unsafe():
    """An unreadable width must not demote a code position it cannot escape."""
    assert (
        _assess('subprocess.run(["bash", "-c", *args])', "run", params="args")
        == VERDICT_UNSAFE
    )
    assert (
        _assess('subprocess.run(["python", "-c", *args])', "run", params="args")
        == VERDICT_UNSAFE
    )


# R7-5 (Important): `_CONFINING` was matched by bare tail name, and it is the one
# check here that grants safety outright — so any project-local helper called
# `basename`, `safe_join` or `secure_filename` cleared the finding, confining or
# not. `shutil.secure_filename` does not even exist.


@pytest.mark.parametrize(
    "body",
    [
        "open(my_utils.basename(name))",
        "open(shutil.secure_filename(name))",
        "open(self.basename(name))",
        "open(helpers.safe_join(ROOT, name))",
        "open(evil.basename(name))",
    ],
)
def test_an_unrecognised_receiver_does_not_grant_confinement(body):
    assert _assess(body, "open", params="name") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body",
    [
        # An unqualified call: a module importing `basename` by name is importing
        # this one.
        "open(basename(name))",
        "open(safe_join(ROOT, name))",
        "open(secure_filename(name))",
        # Qualified by a module that really does provide it.
        "open(os.path.basename(name))",
        "open(posixpath.basename(name))",
        "open(ntpath.basename(name))",
        "open(werkzeug.utils.secure_filename(name))",
        "open(flask.safe_join(ROOT, name))",
        "open(flask.helpers.safe_join(ROOT, name))",
    ],
)
def test_a_recognised_receiver_still_grants_confinement(body):
    assert _assess(body, "open", params="name") == VERDICT_SAFE


# The `deserialize` class had no test of any kind — no `pickle` and no `yaml`
# case anywhere in this file — so nothing pinned the behaviour of two of the six
# registered CG-DESERIALIZE sinks. `exec`, `executescript` and `raw` were
# likewise never exercised.


@pytest.mark.parametrize(
    "body,callee",
    [
        ("pickle.loads(blob)", "pickle.loads"),
        ("pickle.load(blob)", "pickle.load"),
        ("yaml.load(blob)", "yaml.load"),
        ("yaml.load(blob, Loader=yaml.SafeLoader)", "yaml.load"),
        ("pickle.loads(base64.b64decode(blob))", "pickle.loads"),
        ("pickle.loads(data=blob)", "pickle.loads"),
    ],
)
def test_deserializing_user_data_is_unsafe(body, callee):
    """Rebuilding objects from user data can run code; there is no safe
    mechanism to look for, so any tainted argument is unsafe."""
    assert _assess(body, callee, params="blob") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,callee",
    [
        ('pickle.loads(b"\\x80\\x04.")', "pickle.loads"),
        ('yaml.load("a: 1")', "yaml.load"),
    ],
)
def test_deserializing_a_constant_is_safe(body, callee):
    assert _assess(body, callee, params="blob") == VERDICT_SAFE


@pytest.mark.parametrize(
    "body,callee,expected",
    [
        ("exec(src)", "exec", VERDICT_UNSAFE),
        ('exec("pass")', "exec", VERDICT_SAFE),
        ("exec(compile(src, '<s>', 'exec'))", "exec", VERDICT_UNSAFE),
        ("cursor.executescript('SELECT 1')", "executescript", VERDICT_SAFE),
        ("cursor.executescript('SELECT ' + src)", "executescript", VERDICT_UNSAFE),
        ("cursor.executescript(build(src))", "executescript", VERDICT_UNKNOWN),
        ("User.objects.raw('SELECT 1')", "raw", VERDICT_SAFE),
        ("User.objects.raw('SELECT * FROM u WHERE n = %s', [src])", "raw", VERDICT_SAFE),
        ("User.objects.raw('SELECT * FROM u WHERE n = ' + src)", "raw", VERDICT_UNSAFE),
    ],
)
def test_exec_executescript_and_raw(body, callee, expected):
    assert _assess(body, callee, params="src") == expected


@pytest.mark.parametrize(
    "body,callee",
    [
        # An untainted argument whose construction cannot be seen is unknown,
        # never safe — the OPAQUE branch of `_assess_any_tainted_argument`, which
        # produces two of the abstentions the report tabulates.
        ('eval(compile(SRC, "<s>", "eval"))', "eval"),
        ("eval(EXPRESSIONS[key])", "eval"),
        ("exec(load_source())", "exec"),
        ("yaml.load(TEXT, Loader=yaml.SafeLoader)", "yaml.load"),
        ("pickle.loads(PAYLOAD)", "pickle.loads"),
    ],
)
def test_an_opaque_untainted_argument_abstains_rather_than_clearing(body, callee):
    assert _assess(body, callee, params="unused") == VERDICT_UNKNOWN


# --- Fix round 8 ---

# A composed argument built from opaque-but-untainted operands (`eval(a + b)`,
# `pickle.loads(a + b)`, `eval(f"{a}{b}")`) classifies as COMPOSED, not OPAQUE,
# so the old `== OPAQUE` abstention guard cleared it to `safe` outright — a
# silent no-finding in `eval`/`pickle.loads`, the classes with no safe mechanism
# to look for. The guard must abstain on anything that is not provably LITERAL,
# so a composition of unresolved parts surfaces as `-UNVERIFIED`, never `safe`.
#
# The operands here are left *untainted* on purpose: this is precisely the
# operands-opaque-not-tracked case, distinct both from a provable literal
# (`eval("1 + 1")`, which stays safe) and from a tracked-tainted argument
# (`eval(request.args.get("c"))`, which is a confirmed critical). `_assess`
# seeds every parameter as tainted, so these use a taint-free state instead.


def _assess_untainted(body, callee, params):
    src = f"def f({params}):\n    {body}\n"
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    states = snapshot_call_sites(fn)
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    sink = lookup_sink(ast.unparse(call.func), "python")
    assert sink is not None, ast.unparse(call.func)
    return assess_call(sink, call, states[id(call)])


@pytest.mark.parametrize(
    "body,callee",
    [
        ("eval(a + b)", "eval"),
        ("pickle.loads(a + b)", "pickle.loads"),
        ('eval(f"{a}{b}")', "eval"),
    ],
)
def test_a_composed_opaque_argument_abstains_rather_than_clearing(body, callee):
    """COMPOSED-of-opaque is not provably LITERAL, so it must not read as safe."""
    assert _assess_untainted(body, callee, "a, b") == VERDICT_UNKNOWN


def test_eval_of_added_opaque_operands_is_never_a_silent_no_finding():
    """`eval(a + b)` specifically: the exact shape that leaked to `safe`."""
    assert _assess_untainted("eval(a + b)", "eval", "a, b") != VERDICT_SAFE


def test_a_provable_literal_stays_safe_and_a_tracked_tainted_arg_is_critical():
    """The two ends of the lattice the composed-opaque fix must not disturb."""
    assert _assess_untainted('eval("1 + 1")', "eval", "a, b") == VERDICT_SAFE
    assert _assess("eval(a + b)", "eval", params="a, b") == VERDICT_UNSAFE


# --- `_flags_all_known` polarity, the D6 matching machinery -------------------

# `--` is end-of-options, not a flag: `_flags_all_known` skips it explicitly, so
# a known runner whose only "unknown" token is `--` still clears. Deleting that
# skip makes `--` read as an unrecognised flag and drags every `runner ... --
# <arg>` argv from safe to an abstention -- the scope boundary moving in
# silence.


@pytest.mark.parametrize(
    "body,params",
    [
        ('["node", "script.js", "--", userarg]', "userarg"),
        ('["ruby", "app.rb", "--", arg]', "arg"),
        ('["python", "app.py", "--", arg]', "arg"),
    ],
)
def test_a_known_runner_with_double_dash_stays_safe(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_SAFE


# The `known_letters` bundle rule is `all(...)`: a single-dash bundle clears only
# when *every* letter in it is one the runner is known to accept and known not to
# treat as code. Flipping it to `any(...)` lets one recognised letter carry an
# unknown one to safety -- the exact polarity the design turns on, since the set
# is consulted only to GRANT safety.


@pytest.mark.parametrize(
    "body,params",
    [
        # `-lZ`: `l` is known to bash, `Z` is not, so the bundle must abstain.
        ('["bash", "-lZ", cmd]', "cmd"),
        ('["sh", "-lY", cmd]', "cmd"),
    ],
)
def test_an_unknown_letter_in_a_posix_bundle_abstains(body, params):
    assert _assess(f"subprocess.run({body})", "run", params=params) == VERDICT_UNKNOWN
