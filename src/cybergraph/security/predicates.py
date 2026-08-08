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

# Shells and interpreters that take inline code or a library/module to load —
# membership decides shell involvement from argv[0]'s *identity* alone. A flag
# byte has no meaning independent of the program running it (``-i`` is "load a
# library" to gawk and "input file" to ffmpeg), so no allowlist or blocklist
# over argv[1] can ever be correct — see `_is_shell_or_interpreter`.
_SHELL_EXECUTABLES = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox",
    "cmd", "command", "powershell", "pwsh",
    "python", "python2", "python3", "perl", "ruby", "node", "php",
    "awk", "gawk", "mawk",
    "ssh",  # `-o ProxyCommand=...` executes a command.
}

# Keyword names accepted for the argument of interest, per vulnerability class,
# when it did not arrive positionally.
_KEYWORD_NAMES = {
    "sql": ("sql", "query", "statement"),
    "command": ("args",),
    "path": ("file",),
    "template": ("source", "template"),
}


def assess_call(sink: Sink, call: ast.Call, state: CallState | None) -> str:
    """Decide whether this specific call site is an unsafe use of the sink.

    ``state`` is ``None`` for a call ``snapshot_call_sites`` never recorded —
    inside a nested function, for instance. Per its own contract that is
    "maximally conservative", not "clean", so it is unknown here too, never
    safe.
    """
    if state is None:
        return VERDICT_UNKNOWN
    if sink.vuln_class == "sql":
        return _assess_sql(call, state)
    if sink.vuln_class == "command":
        return _assess_command(sink, call, state)
    if sink.vuln_class == "path":
        return _assess_path(call, state)
    if sink.vuln_class == "template":
        return _assess_template(call, state)
    return _assess_any_tainted_argument(call, state)


def _find_argument(call: ast.Call, vuln_class: str) -> ast.expr | None:
    """Locate the argument of interest, positionally or by accepted keyword.

    ``call.args`` being empty means the arguments arrived as keywords, not
    that there are none — a predicate that reads that as "no argument, so
    safe" is exactly the bug this module exists to avoid. Returns ``None``
    when the argument cannot be located at all — an unrecognised vuln class,
    or an unrecognised keyword name — which callers must treat as unknown,
    never safe.
    """
    if call.args:
        return call.args[0]
    for name in _KEYWORD_NAMES.get(vuln_class, ()):
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
    """Shell involvement decides the mechanism; argv[0] decides who picks the binary.

    Shell/interpreter involvement for a list argv is decided from argv[0]'s
    *identity* alone, never from a flag byte — see `_is_shell_or_interpreter`.
    """
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

        argv0 = elements[0] if elements else None
        any_tainted = any(_has_tainted_name(element, state) for element in elements)

        if (
            isinstance(argv0, ast.Constant)
            and isinstance(argv0.value, str)
            and _is_shell_or_interpreter(argv0.value)
        ):
            # The program itself interprets code or arguments as a shell
            # would; which flag is used, and what shell= says, do not change
            # that.
            return VERDICT_UNSAFE if any_tainted else VERDICT_SAFE

        # With shell=True (or a SHELL_INHERENT sink) and tainted argv, the
        # shell IS the mechanism — nothing left to be uncertain about. This
        # must be decided before the non-constant-argv0 fallback below, or a
        # confirmed injection gets demoted to merely unknown.
        if shell and any_tainted:
            return VERDICT_UNSAFE

        if argv0 is not None and not isinstance(argv0, ast.Constant) and any_tainted:
            # argv[0] is not a literal, so its identity cannot be resolved —
            # we cannot rule out it being a shell or interpreter, and no flag
            # inspection can substitute for knowing the program.
            return VERDICT_UNKNOWN

        return VERDICT_SAFE

    if not _has_tainted_name(command, state):
        return VERDICT_SAFE
    if shell:
        return VERDICT_UNSAFE
    # A string command without a shell is passed as the executable name on POSIX
    # and parsed differently on Windows. Not the injection mechanism; not safe.
    return VERDICT_UNKNOWN


def _assess_path(call: ast.Call, state: CallState) -> str:
    """Tainted paths are unsafe unless something actually confines them.

    A confining call only exonerates the tainted names *inside its own
    argument subtree* — ``user_dir + os.path.basename(name)`` still leaks
    ``user_dir`` untouched, and ``os.path.basename("x")`` confines nothing
    relevant just by appearing in the same expression as an unrelated
    tainted ``base``. So confinement is scoped per tainted name, not applied
    to the expression as a whole the moment any confining call is seen
    anywhere in it.
    """
    target = _find_argument(call, "path")
    if target is None:
        return VERDICT_UNKNOWN
    if not _has_tainted_name(target, state):
        return VERDICT_SAFE

    confined_ids: set[int] = set()
    normalised = False
    for node in ast.walk(target):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func).rsplit(".", 1)[-1]
        if name in _CONFINING:
            for confined_arg in [*node.args, *(kw.value for kw in node.keywords)]:
                confined_ids.update(
                    id(descendant)
                    for descendant in ast.walk(confined_arg)
                    if isinstance(descendant, ast.Name)
                )
        elif name in _NORMALISING:
            normalised = True

    tainted_outside_confinement = any(
        isinstance(child, ast.Name) and child.id in state.tainted and id(child) not in confined_ids
        for child in ast.walk(target)
    )
    if not tainted_outside_confinement:
        return VERDICT_SAFE
    return VERDICT_UNKNOWN if normalised else VERDICT_UNSAFE


def _assess_template(call: ast.Call, state: CallState) -> str:
    """Only the template *text* is the injection vector; context values are
    the safe mechanism, so an untainted template is safe whether its
    construction is a known literal or an unresolved opaque reference (a
    module-level constant, ``self.template``, a loader call) —
    ``render_template_string(TEMPLATE, name=user_input)`` is safe because
    ``TEMPLATE`` carries no taint, regardless of how it was built.

    Unlike SQL, a tainted template has no equivalent to a bound parameter: the
    whole rendered string can become interpreted, not just the substituted
    piece, so *any* taint reaching the template argument is unsafe outright —
    do not carry over ``_assess_sql``'s COMPOSED/OPAQUE split for the tainted
    case, only its untainted short-circuit.
    """
    template = _find_argument(call, "template")
    if template is None:
        return VERDICT_UNKNOWN
    if not _has_tainted_name(template, state):
        return VERDICT_SAFE
    return VERDICT_UNSAFE


def _assess_any_tainted_argument(call: ast.Call, state: CallState) -> str:
    """Code execution, deserialization and templates: any user data is unsafe."""
    unknown = False
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if _has_tainted_name(arg, state):
            return VERDICT_UNSAFE
        if not isinstance(arg, ast.Constant) and classify_expr(arg, state.bindings) == OPAQUE:
            unknown = True
    return VERDICT_UNKNOWN if unknown else VERDICT_SAFE


def _is_shell_or_interpreter(argv0: str) -> bool:
    """Does this ``argv[0]`` name a shell or an interpreter that runs inline code?

    Decided from the program's identity alone, never from a flag: a flag byte
    has no meaning independent of the program running it — ``-i`` is "load a
    library" to ``gawk`` and "an input file" to ``ffmpeg``, and ``-m``, ``-y``,
    ``-n``, ``-l`` all make ``powershell.exe`` parse the remainder as source.
    No allowlist or blocklist over flags can be correct; only the program's
    own name tells us anything. Matched on the basename with a ``.exe``
    suffix stripped, case-folded, so ``/bin/bash``, ``BASH.EXE`` and
    ``C:\\Windows\\System32\\cmd.exe`` all hit.
    """
    tail = argv0.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if tail.endswith(".exe"):
        tail = tail[: -len(".exe")]
    return tail in _SHELL_EXECUTABLES


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
