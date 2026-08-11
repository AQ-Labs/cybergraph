"""Lightweight construction provenance for Java sink arguments.

No Java parser: a structural, statement-local classifier over the argument
text, fail-safe on anything it cannot read. It reuses the engine's vocabulary
(LITERAL/COMPOSED/OPAQUE and VERDICT_*) but is deliberately more conservative
than the Python predicates: because Java taint is weaker (intra-method,
line-based), only an all-literal/constant construction is SAFE. A construction
that contains a variable is UNSAFE when taint confirms it is user-controlled
and UNKNOWN otherwise -- never SAFE, and never a confident UNSAFE on an
unresolved variable.

Java has no template-literal interpolation; its idioms are
``String.format(fmt, ...)`` and a ``StringBuilder``/``.append(x)`` chain, so
both are treated the way a JS template literal is treated: COMPOSED, with
their operands as candidate variables. Java string literals are only the
double-quoted form -- there is no raw/backtick string and no ``${}``
interpolation to special-case.

Native deserialization (``ObjectInputStream.readObject``/``readUnshared``)
takes no argument to classify at all -- the danger is the tainted stream
itself reaching the call, not anything about how a string was built -- so it
gets its own two-outcome rule (:func:`assess_deserialization`) rather than
running through :func:`assess`: it can never read SAFE, because a
deserialization sink is never provably safe from construction alone.
"""

from __future__ import annotations

import re

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import Sink

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_STRING_ONLY_RE = re.compile(r'^\s*"[^"]*"\s*$')
_NUMERIC_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
# Java keywords that are also constant literals (booleans, the null
# reference) -- proven literals, and also excluded from candidate variable
# names.
_JAVA_KEYWORDS = frozenset({"true", "false", "null"})
_CONST_LITERAL_KEYWORDS = _JAVA_KEYWORDS
_APPEND_RE = re.compile(r"\.append\s*\(")


def extract_first_arg(source: str, open_paren: int) -> str | None:
    """Return the first top-level argument's source text, or None if unbalanced.

    String-aware (skips ()/,/quotes inside a ``"..."`` string literal or a
    ``'x'`` char literal) so a ')' or ',' inside one does not end the argument
    early.
    """
    depth = 0
    quote: str | None = None
    start = -1
    i = open_paren
    while i < len(source):
        c = source[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
            if depth == 1:
                start = i + 1
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return source[start:i].strip() or None
        elif c == "," and depth == 1:
            return source[start:i].strip() or None
        i += 1
    return None  # unbalanced -> caller treats as UNKNOWN


def extract_all_args(source: str, open_paren: int) -> list[str]:
    """Return every top-level argument's source text, or [] if unbalanced.

    Command-class sinks (``Runtime.exec``, ``ProcessBuilder``) take argv, not
    a single string, so grading them on `extract_first_arg` alone only ever
    sees the program name -- for the shell idiom, the literal ``"sh"`` -- and
    never the tainted argument that follows it. This walks the same
    string/paren-aware scan as `extract_first_arg` but keeps collecting past
    the first top-level comma instead of stopping there.
    """
    depth = 0
    quote: str | None = None
    start = -1
    args: list[str] = []
    i = open_paren
    while i < len(source):
        c = source[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
            if depth == 1:
                start = i + 1
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                tail = source[start:i].strip()
                if tail or args:
                    args.append(tail)
                return args
        elif c == "," and depth == 1:
            args.append(source[start:i].strip())
            start = i + 1
        i += 1
    return []  # unbalanced -> caller treats as UNKNOWN


def classify(arg_text: str) -> str:
    s = arg_text.strip()
    if _STRING_ONLY_RE.match(s):
        return LITERAL
    # A top-level `+` is checked before either call-shaped idiom below, and
    # decides COMPOSED on its own: whether one of its operands *also* happens
    # to look like a `String.format(...)` call or contain the text
    # `.append(` (e.g. inside a string literal, or as a nested sub-call) is
    # irrelevant to the classification of the whole expression, and must
    # never gate whether the `+`'s other operands get examined at all.
    if len(_split_plus(s)) > 1:
        return COMPOSED
    if s.startswith("String.format(") and s.endswith(")"):
        return COMPOSED
    if _append_open_parens(s):
        return COMPOSED
    return OPAQUE


def _is_proven_literal_operand(operand: str) -> bool:
    """True only for a construction that is positively known to be constant.

    A double-quoted string literal, or a numeric/boolean/null constant.
    Anything else -- a bare identifier, a parenthesized expression, a
    bracketed expression, a call, a field access -- is NOT proven literal,
    even if it happens to contain no scannable identifier: absence of a name
    must never be read as proof of literal-ness.
    """
    s = operand.strip()
    if not s:
        return False
    if _STRING_ONLY_RE.match(s):
        return True
    if _NUMERIC_RE.match(s):
        return True
    if s in _CONST_LITERAL_KEYWORDS:
        return True
    return False


def _operand_candidates(operands: list[str]) -> tuple[list[str], bool]:
    """Candidate variable names from non-literal operands.

    Also returns whether any operand is "unresolved": not a proven literal and
    yet contains no identifier at all (e.g. `(1 + 1)` as an operand) -- such an
    operand must never be silently treated as safe just because it has no name
    to check.
    """
    names: list[str] = []
    unresolved = False
    for part in operands:
        p = part.strip()
        if not p or _is_proven_literal_operand(p):
            continue
        idents = _IDENT_RE.findall(p)
        if not idents:
            unresolved = True
            continue
        for ident in idents:
            if ident not in _JAVA_KEYWORDS:
                names.append(ident)
    return names, unresolved


def _plus_operand_candidates(arg_text: str) -> tuple[list[str], bool]:
    """Candidate variable names from non-literal top-level ``+`` operands."""
    return _operand_candidates(_split_plus(arg_text))


def _format_operand_candidates(format_text: str) -> tuple[list[str], bool]:
    """Candidate variable names from ALL of a ``String.format(...)`` call's arguments.

    Unlike a JS template literal, whose leading piece is always a literal
    fragment of the source text, Java's format argument is a normal runtime
    value: ``String.format(userFmt, x)`` and
    ``String.format("SELECT * FROM " + tbl, "x")`` both carry a non-literal
    format. So every argument -- format included -- is assessed with the same
    positive-literal-proof logic; a format that genuinely is a string literal
    is a proven literal and is skipped by `_is_proven_literal_operand` on its
    own, with no special-casing needed here.

    If `_split_call_args` cannot find where the call's arguments end -- an
    unbalanced quote inside one of them, say -- it returns ``None`` rather
    than a partial list, and that must read as unresolved, never as "no
    arguments found, so every (nonexistent) argument is trivially literal."
    """
    args = _split_call_args(format_text)
    if args is None:
        return [], True
    return _operand_candidates(args)


def _append_open_parens(text: str) -> list[int]:
    """Indices of the ``(`` in every real, unquoted ``.append(`` call.

    A plain ``_APPEND_RE.search``/``finditer`` over the raw text is
    quote-unaware: an argument that merely *contains* the text ``.append(``
    inside a string literal -- ``"foo.append(1)" + userInput`` -- would match
    just the same as a genuine ``StringBuilder`` chain, hijacking the append
    branch and silently dropping the real (and here, tainted) operand after
    the ``+``. This walks the same quote-tracking scan `_split_plus` and
    `extract_first_arg` already use, and only recognises ``.append(`` outside
    any ``"..."``/``'...'`` literal.
    """
    positions: list[int] = []
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            i += 1
            continue
        match = _APPEND_RE.match(text, i)
        if match:
            positions.append(match.end() - 1)
            i = match.end()
            continue
        i += 1
    return positions


def _append_operand_candidates(text: str) -> tuple[list[str], bool]:
    """Candidate variable names from every real ``.append(...)`` call's argument.

    A ``StringBuilder`` chain (``sb.append(a).append(b).toString()``) is
    Java's other composing idiom: each appended operand is assessed with the
    same positive-literal-proof logic as a ``+`` operand or a
    ``String.format`` argument. Uses `_append_open_parens` rather than a bare
    regex scan so a `.append(` inside a string literal is never mistaken for
    a real call.

    A detected append site whose own argument does not balance --
    ``sb.append("a).append(userInput)``, where the unterminated ``"a`` string
    swallows everything after it, including the real ``.append(userInput)``
    -- must never be silently dropped from ``operands``: `extract_first_arg`
    returning ``None`` there is exactly the "we could not read this" case
    ``unresolved`` exists for. Dropping it instead of flagging it is what let
    an unreadable append chain fall through to the COMPOSED "every operand is
    a proven literal" branch and read SAFE.
    """
    operands: list[str] = []
    unresolved = False
    for open_paren in _append_open_parens(text):
        arg = extract_first_arg(text, open_paren)
        if arg is None:
            unresolved = True
            continue
        operands.append(arg)
    names, operand_unresolved = _operand_candidates(operands)
    return names, unresolved or operand_unresolved


def variable_names(arg_text: str) -> list[str]:
    """Identifiers from a top-level ``+`` operand, a ``String.format`` call, or a
    ``.append`` chain -- in that priority order, matching `classify`/`assess`.
    """
    s = arg_text.strip()
    parts = _split_plus(s)
    if len(parts) > 1:
        names, _unresolved = _operand_candidates(parts)
        return _dedup(names)
    if s.startswith("String.format(") and s.endswith(")"):
        names, _unresolved = _format_operand_candidates(s)
        return _dedup(names)
    if _append_open_parens(s):
        names, _unresolved = _append_operand_candidates(s)
        return _dedup(names)
    names, _unresolved = _plus_operand_candidates(arg_text)
    return _dedup(names)


def _dedup(names: list[str]) -> list[str]:
    """De-dup a list of names, preserving first-seen order."""
    seen: set[str] = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _split_plus(text: str) -> list[str]:
    """Split on top-level '+', string/paren-aware."""
    parts, depth, quote, buf = [], 0, None, []
    i = 0
    while i < len(text):
        c = text[i]
        if quote is not None:
            buf.append(c)
            if c == "\\":
                if i + 1 < len(text):
                    buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth -= 1
            buf.append(c)
        elif c == "+" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _split_call_args(s: str) -> list[str] | None:
    """Top-level, comma-separated arguments of the first ``(...)`` call in s.

    Mirrors ``extract_first_arg``'s string/paren-aware scan, but returns every
    top-level argument instead of stopping at the first. Used to split
    ``String.format(...)``'s argument list.

    Returns ``None`` -- not a partial list -- if the call never closes (an
    unbalanced quote inside an argument can swallow the rest of the text,
    including the closing ``)``). A caller that treated the empty/partial
    list this used to return as "this call has no arguments" would let it
    fall through to "every (zero) argument is a proven literal" and read
    SAFE; ``None`` forces the caller to treat it as unresolved instead.
    """
    open_paren = s.index("(")
    depth = 0
    quote: str | None = None
    start = -1
    args: list[str] = []
    i = open_paren
    while i < len(s):
        c = s[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
            if depth == 1:
                start = i + 1
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append(s[start:i].strip())
                return args
        elif c == "," and depth == 1:
            args.append(s[start:i].strip())
            start = i + 1
        i += 1
    return None  # unbalanced -> caller must treat as unresolved, never SAFE


def assess(sink: Sink, arg_text: str | None, tainted_names: set[str]) -> str:
    """Verdict for a Java sink call. Only an all-literal/constant construction is SAFE."""
    if arg_text is None:
        return VERDICT_UNKNOWN
    construction = classify(arg_text)
    if construction == LITERAL:
        return VERDICT_SAFE
    if construction == COMPOSED:
        s = arg_text.strip()
        # Same priority order as `classify`: a top-level `+` is resolved on
        # its own operands first, so a `String.format(...)`/`.append(...)`
        # shape embedded *inside* one of them (a nested call, or merely text
        # inside a string literal) never suppresses examination of the
        # operands beside it -- that suppression is the false-SAFE this
        # ordering exists to close.
        parts = _split_plus(s)
        if len(parts) > 1:
            names, unresolved = _operand_candidates(parts)
        elif s.startswith("String.format(") and s.endswith(")"):
            names, unresolved = _format_operand_candidates(s)
        else:
            names, unresolved = _append_operand_candidates(s)
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        if names or unresolved:
            # a candidate variable (resolved or not) or an operand we could not
            # prove literal -> never read as safe
            return VERDICT_UNKNOWN
        # every operand is a proven literal/constant (e.g. `String.format("%d", 1)`)
        return VERDICT_SAFE
    # OPAQUE: candidates are only extracted from a `String.format(...)` call, a
    # `.append(...)` chain, or a `+` operand, so nothing is found in a bare
    # identifier (none of those) even though the whole argument *is* one.
    # Handle that shape directly: a bare identifier can be checked against
    # taint; any other opaque expression (a call, field access, ...) has no
    # name to check and must fail safe rather than read as unconditionally
    # SAFE.
    s = arg_text.strip()
    match = _IDENT_RE.fullmatch(s)
    if match and match.group(0) not in _JAVA_KEYWORDS and match.group(0) in tainted_names:
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN


def assess_command(args: list[str] | None, tainted_names: set[str]) -> str:
    """Verdict for a Java command sink (``Runtime.exec``/``ProcessBuilder``) over ALL arguments.

    `assess` grades a sink on its first argument alone, which is right for a
    single SQL/path string but wrong for argv: it would see only the program
    name and miss a tainted argument anywhere else in the call -- e.g.
    ``new ProcessBuilder("sh", "-c", userInput)`` must not read SAFE just
    because argv[0] is the literal ``"sh"``. This assesses the whole argument
    list instead, reusing `_operand_candidates` / `_is_proven_literal_operand`
    so the same positive-literal-proof invariant holds -- a non-literal
    argument with no scannable identifier is unresolved, never silently SAFE.

    Verdict rule, fail-safe throughout:
    - no arguments (unreadable call) -> UNKNOWN.
    - every argument is a proven literal/constant -> SAFE.
    - otherwise, some argument is not a proven literal -> UNSAFE if a
      candidate name is taint-confirmed, else UNKNOWN.

    In no branch is a non-literal argument ever read as SAFE, which is the
    false-SAFE this function exists to close.
    """
    if not args:
        return VERDICT_UNKNOWN
    if all(_is_proven_literal_operand(a) for a in args):
        return VERDICT_SAFE
    names, _unresolved = _operand_candidates(args)
    if any(n in tainted_names for n in names):
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN


def assess_deserialization(tainted_present: bool) -> str:
    """Verdict for a native deserialization sink (``readObject``/``readUnshared``).

    These take no argument to classify -- the danger is the tainted
    stream/value reaching the call at all, not how a string was built -- so
    there is no construction to prove literal and this can never return
    VERDICT_SAFE. UNSAFE when taint is confirmed, UNKNOWN otherwise: an
    unresolved deserialization call is still not provably safe.
    """
    return VERDICT_UNSAFE if tainted_present else VERDICT_UNKNOWN
