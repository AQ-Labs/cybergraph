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

*A program decides which of its arguments are code, and neither its identity
nor a flag byte decides that alone.* ``["python", "manage.py", "migrate", app]``
runs an interpreter and is not injection, because ``app`` is an argument to
``manage.py``; ``["python", "-c", app]`` is. Only the pair — this program, this
position — settles it.

Which is also the limit of what the AST can settle. Knowing that a command
carrying user data is *safe* means knowing which of that program's flags take
code, and that is knowable for shells and interpreters but not for programs at
large. So the command class is scoped to the runners in ``_CODE_RUNNERS``,
abstains when a runner is named anywhere it cannot account for, and treats
**argument and config injection through some other program's flags**
(``awk -f``, ``ssh -o ProxyCommand=``, ``find -exec``, ``git -c
core.sshCommand=``) as a documented gap for this phase rather than pretending to
a flag table it cannot keep correct. See ``_assess_list_argv``.

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

@dataclass(frozen=True)
class _Runner:
    """A program that runs code handed to it on its own command line.

    Only these are modelled, and the reason is a hard limit rather than a
    shortlist: calling a command that carries user data *safe* means knowing
    which of that program's flags take code, and that cannot be known for
    programs in general. So the table covers the shells and interpreters whose
    whole purpose is running code, and every other program is either abstained
    on (`_names_a_runner`) or out of scope (see `_assess_list_argv`).

    ``code_flags``    flags whose operand is code, matched exactly.
    ``code_prefixes`` canonical flags matched by abbreviation, the way
                      PowerShell resolves ``-Comm`` to ``-Command``.
    ``code_letters``  for the POSIX shells, whose short flags bundle: a
                      single-dash token whose letters include one of these takes
                      code, so ``-c``, ``-lc``, ``-xc`` and ``-eic`` all count.
    ``known_flags``   flags this runner is known to accept and known *not* to
                      treat as code. Consulted only to GRANT safety, so a flag
                      missing from it abstains and never clears — the polarity
                      that stops an incomplete table from becoming a silent
                      miss. Seed it only with flags you are sure about.
    ``known_letters`` the same, for single-dash bundles.
    ``flag_prefixes`` what a flag starts with here — ``/`` for the ``cmd``
                      family only, so a POSIX absolute path is not read as one.
    ``fold_case``     whether flags are case-insensitive (the Windows shells).
    ``takes_rest``    whether a code flag claims every element after it.
                      ``cmd /c`` and ``powershell -Command`` take the remainder
                      of the command line; a POSIX ``sh -c`` takes exactly one
                      string and turns the rest into ``$0``, ``$1`` ….
    """

    code_flags: frozenset[str] = frozenset()
    code_prefixes: tuple[str, ...] = ()
    code_letters: str = ""
    known_flags: frozenset[str] = frozenset()
    known_letters: str = ""
    flag_prefixes: tuple[str, ...] = ("-",)
    fold_case: bool = False
    takes_rest: bool = False


# A POSIX shell reads code after a single-dash bundle containing `c`; a bare
# operand is a script *path*. `--rcfile`/`--init-file` are sourced, so they are
# code too, and are matched exactly rather than by letter — `--norc` contains a
# `c` and takes nothing.
_POSIX_SHELL = _Runner(
    code_flags=frozenset({"--command", "--rcfile", "--init-file"}),
    code_letters="c",
    known_flags=frozenset({
        "--login", "--noprofile", "--norc", "--posix", "--restricted",
        "--verbose", "--debug", "--help", "--version", "--noediting",
        "--dump-strings", "--dump-po-strings", "--pretty-print", "--command",
        "--rcfile", "--init-file", "--protected", "--wordexp", "--interactive",
    }),
    known_letters="abcefhiklmnoprstuvxCDLPO",
)
_WINDOWS_SHELL = _Runner(
    code_flags=frozenset({"/c", "/k"}),
    known_flags=frozenset({
        "/c", "/k", "/q", "/d", "/a", "/u", "/t", "/e", "/f", "/v", "/s", "/x", "/y",
    }),
    flag_prefixes=("/", "-"),
    fold_case=True,
    takes_rest=True,
)
_POWERSHELL = _Runner(
    code_prefixes=("-command", "-encodedcommand"),
    # `-File` takes a *path*, so it belongs here and not in the code set.
    known_flags=frozenset({
        "-file", "-noprofile", "-noninteractive", "-nologo", "-noexit", "-sta",
        "-mta", "-windowstyle", "-executionpolicy", "-version", "-inputformat",
        "-outputformat", "-configurationname", "-settingsfile", "-help", "-?",
        "-workingdirectory", "-loginshell", "-command", "-encodedcommand",
    }),
    fold_case=True,
    takes_rest=True,
)
# `-c` is inline code and `-m` names a module to run, which is code selection.
_PYTHON = _Runner(
    code_flags=frozenset({"-c", "-m"}),
    known_flags=frozenset({
        "-b", "-B", "-d", "-E", "-h", "-i", "-I", "-O", "-OO", "-P", "-q", "-R",
        "-s", "-S", "-u", "-v", "-V", "-W", "-x", "-X", "--version", "--help",
        "--check-hash-based-pycs",
    }),
)

# The flag tokens that make a shell or interpreter *visibly* present even when
# its name cannot be read — a canonical inline-code flag. Deliberately an exact,
# short list rather than a reuse of the per-runner matchers above: those are
# permissive in ways that only make sense once the runner is known (`perl`'s
# "any single-dash flag whose letters include e" classifies `-resize`, `-type`,
# `-name` and `-delete`; the shells' `c` rule classifies `-cf` and
# `-recursive`), and reusing them here would pull ordinary commands into
# abstention. Used only by `_hides_a_runner_before_a_code_flag`.
_VISIBLE_CODE_FLAGS = frozenset({
    "-c", "-lc", "-xc", "-ic", "-eic", "-lxc", "-cx", "-ci",
    "-e", "-E", "-m", "-M", "-r", "-p", "-B", "-R", "-F",
    "--eval", "--command", "--print", "--require", "--rcfile", "--init-file",
})
# The Windows spellings, compared case-insensitively.
_VISIBLE_CODE_FLAGS_FOLDED = frozenset({"/c", "/k", "-command", "-encodedcommand"})

_CODE_RUNNERS: dict[str, _Runner] = {
    # `mksh`, `ksh93` and `xonsh` are spelled out because their trailing text is
    # part of the name, not a version suffix `_deversioned` can strip.
    **{name: _POSIX_SHELL for name in (
        "sh", "bash", "zsh", "dash", "ksh", "ksh93", "mksh", "ash", "fish",
        "csh", "tcsh", "xonsh",
    )},
    **{name: _WINDOWS_SHELL for name in ("cmd", "command")},
    **{name: _POWERSHELL for name in ("powershell", "pwsh")},
    # `ipython` is the same runner family as `python`, not a further name list:
    # leaving it out would silently clear `["ipython", "-c", <tainted>]`, which
    # is inline code to an interpreter and squarely in scope.
    **{name: _PYTHON for name in ("python", "python2", "python3", "ipython")},
    # `-M<module>` loads and runs a module, the same exposure as `python -m`;
    # a single-dash bundle ending in `e` (`-pe`, `-ne`, `-lne`) takes code.
    "perl": _Runner(
        code_flags=frozenset({"-e", "-E", "-M", "-m", "-c", "-r", "--eval"}),
        code_letters="eE",
        known_flags=frozenset({
            "-a", "-C", "-d", "-D", "-F", "-h", "-i", "-I", "-l", "-n", "-p",
            "-s", "-S", "-t", "-T", "-u", "-U", "-v", "-V", "-w", "-W", "-x",
            "-X", "-0", "--help", "--version",
        }),
    ),
    # `-p` is loop mode here, not `node`'s evaluate-and-print, which is why
    # these two cannot share one entry.
    "ruby": _Runner(
        code_flags=frozenset({"-e", "-c", "-r", "--eval"}),
        known_flags=frozenset({
            "-a", "-C", "-d", "-E", "-F", "-h", "-i", "-I", "-K", "-l", "-n",
            "-p", "-s", "-S", "-T", "-U", "-v", "-w", "-W", "-x", "-y", "-0",
            "--version", "--help", "--disable", "--enable", "--verbose", "--debug",
        }),
    ),
    "node": _Runner(
        code_flags=frozenset({
            "-e", "--eval", "-p", "--print", "-r", "--require", "-c", "--check",
        }),
        known_flags=frozenset({
            "-i", "--interactive", "-v", "--version", "-h", "--help",
            "--no-warnings", "--experimental-modules", "--inspect",
            "--inspect-brk", "--max-old-space-size", "--enable-source-maps",
            "--trace-warnings", "--unhandled-rejections",
        }),
    ),
    # `-B`/`-R` are begin/per-line code and `-F` runs a file; `-f` parses one
    # named path and is not code the caller composed.
    "php": _Runner(
        code_flags=frozenset({"-r", "-B", "-R", "-F", "-e", "-c", "--eval"}),
        known_flags=frozenset({
            "-a", "-f", "-h", "-i", "-l", "-m", "-n", "-q", "-s", "-v", "-w",
            "-z", "-d", "-H", "-S", "-t", "--version", "--help",
        }),
    ),
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
    """Report only what the argv itself proves, and abstain everywhere else.

    Deciding that a command carrying user data is *safe* requires knowing which
    of that program's flags take code. For a shell or an interpreter that is
    readable off argv; for programs in general it is not, and three earlier
    attempts to encode it as a growing flag table each fixed their target and
    broke something new. So the scope is cut to the runners in
    ``_CODE_RUNNERS``, and everything else either abstains or falls under the
    documented gap described in ``_assess_list_argv``.
    """
    command = _find_argument(call, "command")
    if command is None:
        return VERDICT_UNKNOWN
    if not _has_tainted_name(command, state):
        return VERDICT_SAFE  # (1) nothing of the user's reaches the command
    shell = _shell_status(sink, call)
    if shell is True:
        return VERDICT_UNSAFE  # (2) the shell is the mechanism, whatever argv says

    if isinstance(command, ast.List | ast.Tuple):
        verdict = _assess_list_argv(list(command.elts), state)
        if shell is None and verdict == VERDICT_SAFE:
            # (2b) Whether a shell runs here cannot be read off the call, and on
            # Windows `shell=True` with a list argv goes through `list2cmdline`
            # into `cmd /c`, so a tainted element carrying `&` is live
            # injection. An unresolved `shell=` must not be able to clear.
            return VERDICT_UNKNOWN
        return verdict

    # (9) A string command with no shell is passed as the executable *name* on
    # POSIX and parsed differently on Windows. Platform-dependent, so not a
    # verdict either way.
    return VERDICT_UNKNOWN


def _assess_list_argv(elements: list[ast.expr], state: CallState) -> str:
    """Decide a list argv, in the order the rules are allowed to fire.

    Two routes reach SAFE while user data is present, and each is deliberately
    fenced:

    *A known runner whose flags are all accounted for* (5). The flag set is
    consulted to **grant** safety, so a flag missing from it lands on (6) and
    abstains. That polarity is the whole design: an incomplete table costs
    detection, never correctness. It is why ``["php", "-r", cmd]`` cannot come
    back safe just because someone forgot ``-r``.

    *A program that names no runner anywhere* (8). This is the accepted scope
    boundary. It sends **argument and config injection** — ``awk -f <tainted>``,
    ``ssh -o ProxyCommand=<tainted>``, ``find -exec``, ``rsync --rsh``,
    ``git -c core.sshCommand=`` — to safe, because separating those from
    ``["git", "show", rev]`` needs exactly the per-program flag semantics this
    module no longer claims to know. That family is a documented gap for this
    phase, not an oversight.

    Rule (7) is why no wrapper list exists: a name list has the wrong polarity,
    since a wrapper nobody thought of would clear ``["newwrapper", "bash", "-c", t]``.
    Looking downstream for the *shell* instead covers ``env``, ``sudo``,
    ``timeout``, ``docker run``, ``kubectl exec`` and every wrapper not yet
    written, with nothing to keep up to date.
    """
    tainted = [index for index, element in enumerate(elements) if _has_tainted_name(element, state)]
    if not tainted:
        return VERDICT_SAFE  # (1)
    starred = any(isinstance(elements[index], ast.Starred) for index in tainted)
    if 0 in tainted and not isinstance(elements[0], ast.Starred):
        return VERDICT_UNSAFE  # (3) the attacker picks the executable

    argv0 = _constant_str(elements[0])
    runner = _runner_for(argv0) if argv0 is not None else None
    if runner is not None:
        if any(index in _code_indices(elements, runner) for index in tainted):
            return VERDICT_UNSAFE  # (4) handed to the runner as code
        if starred or not _flags_all_known(elements, runner):
            return VERDICT_UNKNOWN  # (6) a flag, or a width, we cannot account for
        if any(_constant_str(elements[index - 1]) is None for index in tainted if index > 1):
            # An element we cannot read, immediately left of the tainted one,
            # might be the very code flag that would make it code.
            return VERDICT_UNKNOWN
        return VERDICT_SAFE  # (5)

    if _names_a_runner(elements[1:]):
        return VERDICT_UNKNOWN  # (7) a runner downstream: the wrapper rule
    if _hides_a_runner_before_a_code_flag(elements):
        return VERDICT_UNKNOWN  # (7b) a runner downstream we could not name
    if argv0 is None or starred:
        return VERDICT_UNKNOWN  # (9)
    return VERDICT_SAFE  # (8) names no runner anywhere — see the docstring


def _code_indices(elements: list[ast.expr], runner: _Runner) -> set[int]:
    """Which argv indices this runner is handed as code."""
    code: set[int] = set()
    for index in range(1, len(elements)):
        element = elements[index]
        text = _constant_str(element)
        raw = text if text is not None else _leading_literal(element)
        if raw is None:
            continue
        token = _fold(raw, runner)
        if not any(token.startswith(prefix) for prefix in runner.flag_prefixes):
            continue
        name, separator, _ = token.partition("=")
        if _takes_code(name, runner):
            if separator or text is None:
                code.add(index)  # `-c=x`, or `"-c" + x` bundled into one element
            elif runner.takes_rest:
                code.update(range(index + 1, len(elements)))
            else:
                code.add(index + 1)
        elif _bundled_code(token, runner) is not None:
            code.add(index)  # `-c<code>` in a single token
    return {index for index in code if index < len(elements)}


def _flags_all_known(elements: list[ast.expr], runner: _Runner) -> bool:
    """Is every readable flag here one this runner is known to take, and not code?

    Consulted only to grant safety, so anything unrecognised must answer
    "no" and send the call to an abstention.
    """
    for element in elements[1:]:
        text = _constant_str(element)
        if text is None:
            continue
        token = _fold(text, runner)
        if token == "--" or not any(token.startswith(p) for p in runner.flag_prefixes):
            continue
        name = token.partition("=")[0]
        if _takes_code(name, runner) or _bundled_code(token, runner) is not None:
            continue
        if name in _fold_set(runner.known_flags, runner):
            continue
        if (
            runner.known_letters
            and _is_short_flag(name)
            and all(letter in runner.known_letters for letter in name[1:])
        ):
            continue
        return False
    return True


def _names_a_runner(elements: list[ast.expr]) -> bool:
    """Does any readable element name a code runner? — the generic wrapper rule."""
    for element in elements:
        text = _constant_str(element)
        if text is not None and _runner_for(text) is not None:
            return True
    return False


def _hides_a_runner_before_a_code_flag(elements: list[ast.expr]) -> bool:
    """Is an unreadable program slot followed by a visible inline-code flag?

    Rule 7 finds the shell by *name*, so on its own it misses
    ``["sudo", "-u", "www", shell_var, "-c", cmd]``, where the program is a
    variable — yet the ``-c`` with a tainted operand just after it says a shell
    is there as plainly as the name would have. The element being unreadable is
    the only reason rule 7 came up empty, so this closes that gap rather than
    widening the rule.

    *Later index* is what keeps it narrow, and is the whole difference between
    this and reversing the scope decision. The out-of-scope family — ``sed -e
    <x>``, ``mysql -e <x>``, ``git -c <x> fetch``, ``ssh myhost <x>``, ``awk -f
    <x>`` — puts the unreadable element last, or leaves only non-flags after it,
    so the flag that would incriminate it is always *earlier*. None of those
    move. Firing on a code flag anywhere in argv instead would drag all of them
    from safe to abstaining.

    A ``Starred`` element is unreadable by the same token: ``["sudo", *opts,
    "-c", cmd]`` abstains, since the expansion could be the shell's name.
    """
    for index in range(1, len(elements)):
        if _constant_str(elements[index]) is not None:
            continue  # readable, so rule 7 already had its chance at this one
        for later in elements[index + 1:]:
            text = _constant_str(later)
            if text is not None and (
                text in _VISIBLE_CODE_FLAGS or text.casefold() in _VISIBLE_CODE_FLAGS_FOLDED
            ):
                return True
    return False


def _takes_code(name: str, runner: _Runner) -> bool:
    """Does this flag hand the runner something to run?"""
    if name in _fold_set(runner.code_flags, runner):
        return True
    if len(name) > 1 and any(canonical.startswith(name) for canonical in runner.code_prefixes):
        return True
    if runner.code_letters and _is_short_flag(name):
        return any(letter in name[1:] for letter in runner.code_letters)
    return False


def _bundled_code(token: str, runner: _Runner) -> str | None:
    """A one-letter code flag carrying its value in the same token (``-c<code>``)."""
    for flag in _fold_set(runner.code_flags, runner):
        if len(flag) == 2 and len(token) > 2 and token.startswith(flag):
            return flag
    return None


def _is_short_flag(name: str) -> bool:
    return name.startswith("-") and not name.startswith("--")


def _fold(token: str, runner: _Runner) -> str:
    return token.casefold() if runner.fold_case else token


def _fold_set(flags: frozenset[str], runner: _Runner) -> frozenset[str]:
    if not runner.fold_case:
        return flags
    return frozenset(flag.casefold() for flag in flags)


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


def _deversioned(name: str) -> str | None:
    """``python3.11`` → ``python``; ``None`` when there is no suffix to strip.

    A trailing run of digits and dots, and any ``-`` or ``_`` joining it to the
    name, is a release number rather than a different program.
    """
    stripped = name.rstrip("0123456789.").rstrip("-_")
    return stripped if stripped and stripped != name else None


def _runner_for(text: str) -> _Runner | None:
    """The runner this program name denotes, if any.

    The raw basename is tried first, so an exact entry always wins, and only
    then the name with a version suffix removed: ``python3.11``, ``php8.2``,
    ``node20``, ``perl5``, ``ruby3.1`` are the same runners as their unversioned
    spellings, and ``python3.11 -c <tainted>`` is inline code to an interpreter
    by any reading.

    Normalising is the fix here rather than a longer table, and the difference
    is polarity, not taste. ``_CODE_RUNNERS`` is consulted to prove DANGER, so a
    name missing from it falls through to rule 8 and reads *safe* — a table has
    to be complete to be correct, and no list of interpreter names survives next
    year's release. A normalisation rule carries no such debt.
    """
    name = _program_name(text)
    runner = _CODE_RUNNERS.get(name)
    if runner is not None:
        return runner
    base = _deversioned(name)
    return _CODE_RUNNERS.get(base) if base is not None else None


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


def _shell_status(sink: Sink, call: ast.Call) -> bool | None:
    """Does a shell run here: yes, no, or unreadable?

    Three states, and the third is the whole point. This is consulted to prove
    DANGER, so anything it cannot resolve must not come back as *no shell*: that
    answer sends a list argv on to rule 8 and out as ``safe``.

    ``subprocess`` tests ``shell`` for truth, not for identity, so ``shell=1``
    and ``shell="yes"`` run a shell exactly as ``shell=True`` does — the earlier
    ``value is True`` comparison read both as no shell. A value that is not a
    constant (``shell=self.use_shell``, ``shell=os.name == "nt"``) cannot be
    resolved from the AST, and neither can a ``**kwargs`` that may well carry
    ``shell=True``; both are unreadable, never absent.
    """
    if sink.shell == SHELL_INHERENT:
        return True
    if sink.shell != SHELL_CONDITIONAL:
        return False
    for keyword in call.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant):
                return bool(keyword.value.value)
            return None
    if any(keyword.arg is None for keyword in call.keywords):
        return None  # `**kwargs` may carry `shell=`
    return False
