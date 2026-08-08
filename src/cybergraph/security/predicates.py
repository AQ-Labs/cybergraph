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

*A program decides which of its arguments are code, and the program is not
always at position 0.* ``["python", "manage.py", "migrate", app]`` runs an
interpreter and is not injection, because ``app`` is an argument to
``manage.py``; ``["env", "bash", "-c", cmd]`` is injection, because the shell
sits one slot right of a wrapper. Neither the program's identity on its own nor
a flag byte on its own decides anything — the pair does. See
``_resolve_program`` and ``_code_positions``.

Three outcomes, and the third is load-bearing: a value whose construction cannot
be seen is ``unknown``, never ``safe``. In particular, an argument that arrives
as a keyword (``cursor.execute(sql=...)``) is not an absent argument, and a
call site whose argument of interest cannot be located at all is ``unknown``,
never ``safe`` — the absence of a match is not evidence of safety.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE, CallState, classify_expr
from cybergraph.security.sinks import SHELL_CONDITIONAL, SHELL_INHERENT, Sink

VERDICT_SAFE = "safe"
VERDICT_UNSAFE = "unsafe"
VERDICT_UNKNOWN = "unknown"

# These reduce an arbitrary path to something inside a known directory.
_CONFINING = {"basename", "safe_join", "secure_filename"}
# These canonicalise without restricting where the result points.
_NORMALISING = {"abspath", "normpath", "realpath", "expanduser", "resolve"}

# Which bare (non-flag) operands a program treats as code.
_NO_BARE = "none"
_FIRST_BARE = "first"
_ALL_BARE = "all"


@dataclass(frozen=True)
class _ProgramSpec:
    """Which argv positions one program treats as code, as data not as branches.

    ``code_flags``      flag tokens whose *operand* is code (``-c``, ``-exec``);
                        a word with no dash counts too, for ``deno eval``.
    ``code_prefixes``   canonical long flags matched by abbreviation, the way
                        PowerShell resolves ``-Comm`` to ``-Command``.
    ``code_letters``    for the POSIX shell family, whose flags bundle: any flag
                        whose letters include one of these takes code, so
                        ``-lc``, ``-xc``, ``-ic`` and ``-eic`` all count.
    ``bare_is_code``    whether the first bare operand is code (``awk`` runs its
                        first operand), all of them are (``ssh`` sends every
                        operand after the host to a remote shell), or none is
                        (``python script.py`` names a *path*).
    ``program_flags``   flags that supply the program some other way, so the
                        bare operand stops being code: after ``awk -f prog.awk``
                        the operands are data files.
    ``flag_prefixes``   what a flag starts with — ``/`` for the ``cmd`` family.
    ``fold_case``       whether flags are case-insensitive (Windows shells).
    ``flag_takes_rest`` whether a code flag claims every element after it, not
                        just the next one. ``cmd /c`` and ``powershell
                        -Command`` take the remainder of the command line, so
                        ``["cmd", "/c", "dir", x]`` runs ``x``; a POSIX ``sh -c``
                        takes exactly one string and turns the rest into ``$0``,
                        ``$1`` …, which are values, not code.
    ``guard_unread``    whether an *unreadable* element immediately before the
                        value in question forces an abstention, because it
                        might have been a code flag. True for programs whose
                        job is running code — missing ``["bash", flag, cmd]``
                        is a silent miss. False where the code exposure is
                        incidental (``git -c``, ``tar -I``, ``rsync -e``): an
                        abstention there would swallow ``git clone url dest``
                        and every other pair of adjacent variable operands.
    """

    code_flags: frozenset[str] = frozenset()
    code_prefixes: tuple[str, ...] = ()
    code_letters: str = ""
    bare_is_code: str = _NO_BARE
    program_flags: frozenset[str] = frozenset()
    flag_prefixes: tuple[str, ...] = ("-",)
    fold_case: bool = False
    flag_takes_rest: bool = False
    guard_unread: bool = False

    @property
    def has_code_positions(self) -> bool:
        return bool(
            self.code_flags
            or self.code_prefixes
            or self.code_letters
            or self.bare_is_code != _NO_BARE
        )


# A POSIX shell reads code after any flag bundle containing `c`; a bare operand
# is a script *path*, not code.
_POSIX_SHELL = _ProgramSpec(code_letters="c", guard_unread=True)
# `-e`/`--eval`/`-r`/`eval` cover the inline-code and preload flags of the
# scripting interpreters; a bare operand is a script path. `eval` has no dash:
# `deno eval <code>` spells it as a subcommand.
_EVAL_INTERPRETER = _ProgramSpec(
    code_flags=frozenset({"-e", "-c", "-r", "--eval", "eval"}), guard_unread=True
)
_AWK_FLAGS = frozenset({"-f", "--file", "-e", "--source", "-i", "--include", "-E"})
_SED_FLAGS = frozenset({"-e", "--expression", "-f", "--file"})

# Programs whose *first operand* selects the real program, so resolution
# continues past them when that operand names something we know.
_MULTIPLEXERS = frozenset({"busybox"})

# Programs that run another program, so the effective program sits further
# right. Their own options and operands are skipped conservatively.
_WRAPPERS = frozenset({
    "env", "sudo", "doas", "nohup", "nice", "ionice", "setsid", "stdbuf",
    "timeout", "flock", "chroot", "unbuffer", "script", "wsl", "xargs",
    "docker", "podman", "kubectl",
})

# Container tools only run a program the caller named under some subcommands.
# `docker run … sh -c cmd` wraps a shell; `docker build -t tag .` does not wrap
# anything, and treating it as a wrapper turns every `docker build` and
# `kubectl get` into an abstention.
_SUBCOMMAND_WRAPPERS: dict[str, frozenset[str]] = {
    "docker": frozenset({"run", "exec", "create", "attach", "start"}),
    "podman": frozenset({"run", "exec", "create", "attach", "start"}),
    "kubectl": frozenset({"run", "exec", "debug", "attach"}),
}

_PROGRAMS: dict[str, _ProgramSpec] = {
    # POSIX shell family.
    **{name: _POSIX_SHELL for name in (
        "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh", "busybox",
    )},
    # Windows command processors: `/c` and `/k` take a command line.
    **{name: _ProgramSpec(
        code_flags=frozenset({"/c", "/k"}), flag_prefixes=("/", "-"), fold_case=True,
        flag_takes_rest=True, guard_unread=True,
    ) for name in ("cmd", "command")},
    # PowerShell resolves flags by unambiguous abbreviation; `-File` is a path.
    **{name: _ProgramSpec(
        code_prefixes=("-command", "-encodedcommand"), fold_case=True,
        flag_takes_rest=True, guard_unread=True,
    ) for name in ("powershell", "pwsh")},
    # `-c` is inline code and `-m` is a module name, which is code selection;
    # a bare operand is a script path.
    **{name: _ProgramSpec(
        code_flags=frozenset({"-c", "-m"}), guard_unread=True,
    ) for name in ("python", "python2", "python3", "ipython")},
    **{name: _EVAL_INTERPRETER for name in (
        "perl", "ruby", "node", "deno", "bun", "php", "lua", "luajit",
        "groovy", "scala", "expect", "tclsh", "wish",
    )},
    **{name: _ProgramSpec(code_flags=frozenset({"-e"}), guard_unread=True) for name in (
        "r", "rscript", "osascript",
    )},
    # awk's first operand *is* the program text — unless a program file or
    # `--source` supplied it, after which operands are data files.
    **{name: _ProgramSpec(
        code_flags=_AWK_FLAGS, bare_is_code=_FIRST_BARE, program_flags=_AWK_FLAGS,
        guard_unread=True,
    ) for name in ("awk", "gawk", "mawk", "nawk")},
    "sed": _ProgramSpec(
        code_flags=_SED_FLAGS, bare_is_code=_FIRST_BARE, program_flags=_SED_FLAGS,
        guard_unread=True,
    ),
    # `-exec` runs everything up to the terminating `;`, not one element.
    "find": _ProgramSpec(
        code_flags=frozenset({"-exec", "-execdir", "-ok"}), flag_takes_rest=True,
    ),
    # `-o ProxyCommand=...` and `-e` run a command locally; every operand after
    # the host reaches a remote shell, and a tainted host is `-o` injection.
    "ssh": _ProgramSpec(code_flags=frozenset({"-o", "-e"}), bare_is_code=_ALL_BARE),
    # Same `-o`/`-e` exposure, but their operands are file paths, not a remote
    # command line.
    **{name: _ProgramSpec(code_flags=frozenset({"-o", "-e"})) for name in ("scp", "rsync")},
    **{name: _ProgramSpec(code_flags=frozenset({"-c", "--eval", "--cmd"})) for name in (
        "vim", "ex", "emacs",
    )},
    "ed": _ProgramSpec(
        code_flags=frozenset({"-c", "--eval"}), bare_is_code=_FIRST_BARE,
    ),
    **{name: _ProgramSpec(code_flags=frozenset({"-f", "-P"})) for name in ("make", "cmake")},
    **{name: _ProgramSpec(
        code_flags=frozenset({"-e", "-c", "--execute", "--command"}),
    ) for name in ("mysql", "psql")},
    **{name: _ProgramSpec(code_flags=frozenset({"-e"})) for name in ("nc", "ncat")},
    "socat": _ProgramSpec(code_flags=frozenset({"-e"}), bare_is_code=_FIRST_BARE),
    "tar": _ProgramSpec(
        code_flags=frozenset({"-I", "--to-command", "--use-compress-program"}),
    ),
    # `-c` sets config, and `core.sshCommand=` in config runs a command.
    "git": _ProgramSpec(
        code_flags=frozenset({"-c", "--exec-path", "--upload-pack", "--receive-pack"}),
    ),
    # Windows script hosts run their first operand.
    **{name: _ProgramSpec(bare_is_code=_FIRST_BARE, guard_unread=True) for name in (
        "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    )},
    # Deliberately empty: `java -jar app.jar` names an archive *path*, and
    # `-cp` a search path. Neither is code the caller composed, so a tainted
    # operand here is not command injection.
    "java": _ProgramSpec(),
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
    """Shell involvement decides the mechanism; the program decides which argv is code."""
    command = _find_argument(call, "command")
    if command is None:
        return VERDICT_UNKNOWN
    shell = sink.shell == SHELL_INHERENT or (
        sink.shell == SHELL_CONDITIONAL and _keyword_is_true(call, "shell")
    )

    if isinstance(command, ast.List | ast.Tuple):
        return _assess_list_argv(list(command.elts), state, shell=shell)

    if not _has_tainted_name(command, state):
        return VERDICT_SAFE
    if shell:
        return VERDICT_UNSAFE
    # A string command without a shell is passed as the executable name on POSIX
    # and parsed differently on Windows. Not the injection mechanism; not safe.
    return VERDICT_UNKNOWN


def _assess_list_argv(elements: list[ast.expr], state: CallState, *, shell: bool) -> str:
    """Decide a list argv from the effective program and the positions it runs.

    Neither half decides alone. ``argv[0]``'s identity on its own says
    ``["python", "manage.py", "migrate", app]`` is critical, which is wrong 23
    times out of 25 in ordinary code; ``argv[0]``'s *position* on its own says
    ``["env", "bash", "-c", cmd]`` is fine, which misses the shell sitting one
    slot right. So: find the program wherever it is, then ask that program
    which of its operands it runs.

    Order matters. A tainted ``argv[0]`` and an explicit shell are both
    conclusive whatever the program turns out to be, so they come first. The
    program decision then comes ahead of the starred-element check, so
    ``["bash", "-c", *args]`` — provably code — is not demoted to an
    abstention alongside ``["git", *args]``, where the starred slot could
    expand to anything.
    """
    if elements and not isinstance(elements[0], ast.Starred):
        if _has_tainted_name(elements[0], state):
            return VERDICT_UNSAFE  # the attacker picks the executable
    tainted = [index for index, element in enumerate(elements) if _has_tainted_name(element, state)]
    if shell and tainted:
        # The shell IS the mechanism; nothing about argv can make it otherwise.
        return VERDICT_UNSAFE
    if not tainted:
        return VERDICT_SAFE

    resolved = _resolve_program(elements)
    if resolved is None:
        # Either argv[0] is not a literal, or a wrapper's own arguments hid the
        # program. Without the program, no position means anything.
        return VERDICT_UNKNOWN
    program_index, program = resolved
    if program_index in tainted:
        return VERDICT_UNSAFE  # the attacker picks the executable

    spec = _PROGRAMS.get(program)
    if spec is None or not spec.has_code_positions:
        # A named program with no position it treats as code: a tainted operand
        # is data to it. A starred element is still unread, so it abstains.
        if any(isinstance(elements[index], ast.Starred) for index in tainted):
            return VERDICT_UNKNOWN
        return VERDICT_SAFE

    code, unread = _code_positions(elements, program_index + 1, spec)
    if any(index in code for index in tainted):
        return VERDICT_UNSAFE
    for index in tainted:
        if isinstance(elements[index], ast.Starred):
            # Unknown width: the expansion could land in a code position.
            return VERDICT_UNKNOWN
        if spec.guard_unread and index - 1 in unread:
            # The element to its left might have been a code flag, which would
            # make this one that flag's operand.
            return VERDICT_UNKNOWN
    return VERDICT_SAFE


def _resolve_program(elements: list[ast.expr]) -> tuple[int, str] | None:
    """Find the argv index of the program that will actually run, and its name.

    ``argv[0]`` is only the program when nothing wraps it. ``env``, ``sudo``,
    ``timeout``, ``docker run`` and the rest run something else, so the shell
    in ``["sudo", "-u", "www", "bash", "-c", cmd]`` is at index 3 and reading
    index 0 sees ``sudo`` and finds nothing. Their own flags and operands vary
    per wrapper (``-u www``, a bare ``5`` for ``timeout``, a subcommand and an
    image for ``docker``), so rather than model each one, every constant token
    inside a wrapper prefix is skipped until a name we have a spec for appears.

    Returns ``None`` when the program cannot be located confidently: a token
    that is not a literal string stops the scan, because guessing past it
    would be guessing which slot holds the program.
    """
    index = 0
    in_wrapper_prefix = False
    while index < len(elements):
        text = _constant_str(elements[index])
        if text is None:
            return None
        name = _program_name(text)
        if name in _MULTIPLEXERS:
            following = (
                _constant_str(elements[index + 1]) if index + 1 < len(elements) else None
            )
            if following is not None and _program_name(following) in _PROGRAMS:
                index += 1  # `busybox sh -c ...` — the real program is the operand
                continue
            return index, name
        if name in _PROGRAMS:
            return index, name
        if name in _WRAPPERS:
            wraps = _wraps_a_program(name, elements, index)
            if wraps is None:
                return None  # a container subcommand we could not read
            if wraps:
                in_wrapper_prefix = True
                index += 1
                continue
            return index, name  # `docker build …`: nothing here wraps a program
        if not in_wrapper_prefix:
            # A literal program we have no spec for. Its identity is known,
            # which is all the decision needs: it has no code positions.
            return index, name
        index += 1
    return None


def _wraps_a_program(name: str, elements: list[ast.expr], index: int) -> bool | None:
    """Is this wrapper, here, actually about to run a program the caller named?

    ``True`` yes, ``False`` no (so it is the effective program itself),
    ``None`` its subcommand could not be read, so neither answer is honest.
    """
    subcommands = _SUBCOMMAND_WRAPPERS.get(name)
    if subcommands is None:
        return True
    following = _constant_str(elements[index + 1]) if index + 1 < len(elements) else None
    if following is None:
        return None
    return following.casefold() in subcommands


def _code_positions(
    elements: list[ast.expr], start: int, spec: _ProgramSpec
) -> tuple[set[int], set[int]]:
    """Which argv indices this program treats as code, and which it could not read.

    The second return value is every index whose token is not a literal string.
    A code flag consumes exactly one following element, so an unread element
    only puts the element *immediately after it* in doubt — which is why the
    caller checks the tainted value's left-hand neighbour rather than treating
    the whole tail as ambiguous.
    """
    code: set[int] = set()
    unread: set[int] = set()
    program_supplied = False
    bare_seen = False
    index = start
    while index < len(elements):
        element = elements[index]
        text = _constant_str(element)
        if text is None:
            unread.add(index)
        token = text if text is not None else _leading_literal(element)
        name, separator, _ = token.partition("=") if token is not None else ("", "", "")
        bundled = _bundled_code_flag(token, spec) if token is not None else None
        if bundled is not None:
            # `-oProxyCommand=...`, `-cprint(1)`: a short flag carrying its own
            # value, so the code is inside this element rather than after it.
            if _folded(bundled, spec) in _folded_flags(spec.program_flags, spec):
                program_supplied = True
            code.update(range(index, len(elements)) if spec.flag_takes_rest else {index})
            index += 1
            continue
        if token is not None and _is_code_flag(name, spec):
            if _folded(name, spec) in _folded_flags(spec.program_flags, spec):
                program_supplied = True
            attached = bool(separator) or text is None
            first_code = index if attached else index + 1
            if spec.flag_takes_rest:
                code.update(range(first_code, len(elements)))
                break
            code.add(first_code)
            index = first_code + 1
            continue
        if token is not None and _looks_like_flag(token, spec):
            index += 1  # a flag of this program that takes no code
            continue
        wants_bare = spec.bare_is_code == _ALL_BARE or (
            spec.bare_is_code == _FIRST_BARE and not bare_seen
        )
        if wants_bare and not program_supplied:
            code.add(index)
        bare_seen = True
        index += 1
    return code, unread


def _bundled_code_flag(token: str, spec: _ProgramSpec) -> str | None:
    """A single-letter code flag with its value bundled into the same token.

    POSIX short options carry their operand attached as often as separated:
    ``ssh -oProxyCommand=...``, ``python -cprint(1)``, ``awk -fprog.awk``. Read
    only as far as the flag itself, so a *tainted* remainder is code sitting in
    this very element and not in the next one.
    """
    folded = _folded(token, spec)
    for flag in _folded_flags(spec.code_flags, spec):
        if len(flag) == 2 and len(folded) > 2 and folded.startswith(flag):
            return flag
    return None


def _looks_like_flag(token: str, spec: _ProgramSpec) -> bool:
    return any(token.startswith(prefix) for prefix in spec.flag_prefixes)


def _folded(token: str, spec: _ProgramSpec) -> str:
    return token.casefold() if spec.fold_case else token


def _folded_flags(flags: frozenset[str], spec: _ProgramSpec) -> frozenset[str]:
    if not spec.fold_case:
        return flags
    return frozenset(flag.casefold() for flag in flags)


def _is_code_flag(name: str, spec: _ProgramSpec) -> bool:
    """Does this flag hand the program something to run?

    Three matching rules, because three families spell flags differently: exact
    tokens, PowerShell's unambiguous-abbreviation prefixes, and the POSIX
    shells' bundled letters, where the ``c`` in ``-lc`` is the same ``c`` as in
    ``-c``.
    """
    folded = _folded(name, spec)
    if folded in _folded_flags(spec.code_flags, spec):
        return True
    if len(folded) > 1 and any(
        canonical.startswith(folded) for canonical in spec.code_prefixes
    ):
        return True
    if spec.code_letters and name.startswith("-"):
        letters = name.lstrip("-")
        return any(letter in letters for letter in spec.code_letters)
    return False


def _constant_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _leading_literal(node: ast.expr) -> str | None:
    """The literal text an expression is known to start with, if any.

    ``"--exec-path=" + tainted`` is not a constant, but its flag name is
    perfectly readable and its value is attached to it.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_literal(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _leading_literal(node.values[0])
    return None


def _program_name(text: str) -> str:
    """The comparable name of a program path: basename, case-folded, unsuffixed."""
    tail = text.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".exe", ".com"):
        if tail.endswith(suffix):
            return tail[: -len(suffix)]
    return tail


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
