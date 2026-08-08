"""Per-sink unsafe-use predicates.

Reaching a sink is inventory; using it unsafely is a vulnerability. A single
"is any argument tainted" test reports correctly parameterized SQL and
``subprocess.run([...], shell=False)`` as critical findings, which is why this
module exists.

Two distinctions the obvious implementation gets wrong:

*Confinement is not normalisation.* ``normpath("../../etc/passwd")`` is still
traversal and ``realpath`` resolves symlinks without restricting the result to
any directory. Only ``basename``, ``safe_join`` and ``secure_filename`` confine.

*Shell involvement is per-API and per-argv.* ``os.system`` always runs a shell;
``subprocess.run`` depends on ``shell=``; and ``["sh", "-c", x]`` runs a shell
whatever the keyword says.

Three outcomes, and the third is load-bearing: a value whose construction cannot
be seen is ``unknown``, never ``safe``. In particular, an argument that arrives
as a keyword (``cursor.execute(sql=...)``) is not an absent argument, and a
call site whose argument of interest cannot be located at all is ``unknown``,
never ``safe`` — the absence of a match is not evidence of safety.
"""

from __future__ import annotations

import ast

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE, CallState, classify_expr
from cybergraph.security.sinks import SHELL_CONDITIONAL, SHELL_INHERENT, Sink

VERDICT_SAFE = "safe"
VERDICT_UNSAFE = "unsafe"
VERDICT_UNKNOWN = "unknown"

# These reduce an arbitrary path to something inside a known directory.
_CONFINING = {"basename", "safe_join", "secure_filename"}
# These canonicalise without restricting where the result points.
_NORMALISING = {"abspath", "normpath", "realpath", "expanduser", "resolve"}

_SHELL_EXECUTABLES = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell"}
_SHELL_FLAGS = {"-c", "/c", "-Command"}

# Keyword names accepted for the argument of interest, per vulnerability class,
# when it did not arrive positionally.
_KEYWORD_NAMES = {
    "sql": ("sql", "query", "statement"),
    "command": ("args",),
    "path": ("file",),
}


def assess_call(sink: Sink, call: ast.Call, state: CallState) -> str:
    """Decide whether this specific call site is an unsafe use of the sink."""
    if sink.vuln_class == "sql":
        return _assess_sql(call, state)
    if sink.vuln_class == "command":
        return _assess_command(sink, call, state)
    if sink.vuln_class == "path":
        return _assess_path(call, state)
    return _assess_any_tainted_argument(call, state)


def _find_argument(call: ast.Call, vuln_class: str) -> ast.expr | None:
    """Locate the argument of interest, positionally or by accepted keyword.

    ``call.args`` being empty means the arguments arrived as keywords, not
    that there are none — a predicate that reads that as "no argument, so
    safe" is exactly the bug this module exists to avoid. Returns ``None``
    when the argument cannot be located at all, which callers must treat as
    unknown, never safe.
    """
    if call.args:
        return call.args[0]
    for name in _KEYWORD_NAMES[vuln_class]:
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
    return None


def _assess_sql(call: ast.Call, state: CallState) -> str:
    """Only the query *text* matters. Parameter values are the safe mechanism."""
    query = _find_argument(call, "sql")
    if query is None:
        return VERDICT_UNKNOWN
    construction = classify_expr(query, state.bindings)
    if construction == LITERAL:
        return VERDICT_SAFE
    if not _has_tainted_name(query, state):
        return VERDICT_SAFE
    return VERDICT_UNSAFE if construction == COMPOSED else VERDICT_UNKNOWN


def _assess_command(sink: Sink, call: ast.Call, state: CallState) -> str:
    """Shell involvement decides the mechanism; argv[0] decides who picks the binary."""
    command = _find_argument(call, "command")
    if command is None:
        return VERDICT_UNKNOWN
    shell = sink.shell == SHELL_INHERENT or (
        sink.shell == SHELL_CONDITIONAL and _keyword_is_true(call, "shell")
    )

    if isinstance(command, ast.List | ast.Tuple):
        elements = list(command.elts)
        if any(
            isinstance(element, ast.Starred) and _has_tainted_name(element, state)
            for element in elements
        ):
            # Tainted argv[1:] injected as extra arguments is argument
            # injection even with shell=False and a clean argv[0] — a class
            # this module cannot fully characterise from the AST alone.
            return VERDICT_UNKNOWN
        if elements and _has_tainted_name(elements[0], state):
            return VERDICT_UNSAFE  # the attacker picks the executable
        if _invokes_a_shell(elements) and any(
            _has_tainted_name(element, state) for element in elements[1:]
        ):
            return VERDICT_UNSAFE  # sh -c <tainted>, whatever shell= says
        if (
            elements
            and not isinstance(elements[0], ast.Constant)
            and any(_has_tainted_name(element, state) for element in elements)
        ):
            # A non-constant argv[0] might itself be a shell executable
            # (e.g. a variable holding "sh"); we can't rule that out, and the
            # rest of argv carries taint, so this is not provably safe.
            return VERDICT_UNKNOWN
        if shell and any(_has_tainted_name(element, state) for element in elements):
            return VERDICT_UNSAFE
        return VERDICT_SAFE

    if not _has_tainted_name(command, state):
        return VERDICT_SAFE
    if shell:
        return VERDICT_UNSAFE
    # A string command without a shell is passed as the executable name on POSIX
    # and parsed differently on Windows. Not the injection mechanism; not safe.
    return VERDICT_UNKNOWN


def _assess_path(call: ast.Call, state: CallState) -> str:
    """Tainted paths are unsafe unless something actually confines them."""
    target = _find_argument(call, "path")
    if target is None:
        return VERDICT_UNKNOWN
    if not _has_tainted_name(target, state):
        return VERDICT_SAFE
    normalised = False
    for node in ast.walk(target):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func).rsplit(".", 1)[-1]
        if name in _CONFINING:
            return VERDICT_SAFE
        if name in _NORMALISING:
            normalised = True
    return VERDICT_UNKNOWN if normalised else VERDICT_UNSAFE


def _assess_any_tainted_argument(call: ast.Call, state: CallState) -> str:
    """Code execution, deserialization and templates: any user data is unsafe."""
    unknown = False
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if _has_tainted_name(arg, state):
            return VERDICT_UNSAFE
        if not isinstance(arg, ast.Constant) and classify_expr(arg, state.bindings) == OPAQUE:
            unknown = True
    return VERDICT_UNKNOWN if unknown else VERDICT_SAFE


def _invokes_a_shell(elements: list[ast.expr]) -> bool:
    """``["sh", "-c", ...]`` runs a shell regardless of the ``shell=`` keyword."""
    if len(elements) < 2:
        return False
    first, second = elements[0], elements[1]
    if not (isinstance(second, ast.Constant) and isinstance(second.value, str)):
        return False
    if second.value not in _SHELL_FLAGS:
        return False
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        executable = first.value.rsplit("/", 1)[-1].lower()
        return executable in _SHELL_EXECUTABLES
    return False


def _has_tainted_name(node: ast.AST, state: CallState) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in state.tainted
        for child in ast.walk(node)
    )


def _keyword_is_true(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name:
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False
