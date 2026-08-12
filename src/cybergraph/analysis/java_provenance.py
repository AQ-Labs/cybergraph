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
# Any bareword call, dotted or bare: matches `append(`/`substring(` in a
# member chain, and `format(` inside `String.format(`. Deliberately broader
# than `_APPEND_RE` -- this is what makes the operand-extraction coverage
# check in `_chain_operand_candidates` a single shared guard rather than a
# per-idiom special case: it finds a *trailing* `.substring(evil)` after a
# recognised append/format chain exactly the same way it finds the
# recognised chain itself.
_CALL_RE = re.compile(r"[A-Za-z_]\w*\s*\(")
# A "gap" between (or before/after) recognised calls is safe to skip only
# when it is pure chain navigation -- method names and the dots connecting
# them (`.`, `.toString`) -- never anything else. This regex only decides
# nav-vs-structural (brackets, stray quotes, operators are flagged); the
# leading gap of a chain is examined further by `_chain_receiver`, because the
# *receiver* it carries (`sb` in `sb.append(x)`) is a real data operand whose
# prior state feeds the resulting string and so must be taint-checked, not
# waved through as navigation.
_NAV_ONLY_RE = re.compile(r"^[\s.\w]*$")


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


def _matching_close_paren(text: str, open_paren: int) -> int | None:
    """Index of the ``)`` matching the ``(`` at ``open_paren``, or None if unbalanced.

    Quote/paren-aware like `extract_first_arg`, but returns only the
    boundary, not the argument text: `_chain_operand_candidates` uses this to
    advance its coverage cursor past the whole call, and separately splits the
    call's argument list on top-level commas (via `extract_all_args`) so each
    argument is tested individually.
    """
    depth = 0
    quote: str | None = None
    i = open_paren
    while i < len(text):
        c = text[i]
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
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None  # unbalanced -> caller must treat as unresolved, never SAFE


_TRAILING_IDENT_RE = re.compile(r"\w+\s*$")


def _chain_receiver(leading_gap: str) -> str | None:
    """The receiver operand of a call chain, or None when it is genuinely inert.

    ``leading_gap`` is the text before the first call's ``(`` -- a nav-only
    span (`_NAV_ONLY_RE`) of the form ``<receiver>.<method>`` (`sb.append`),
    a bare ``<method>`` (`format`, `buildQuery`), or a construction
    (`new StringBuilder`). The method name is the trailing identifier; what
    precedes it, minus the connecting dot, is the receiver expression.

    Returns None -- SAFE-eligible, inert -- for:
      * no receiver at all (a bare call), OR
      * exactly ``String`` (the static ``String.format``/``join``/``valueOf``/
        ``copyValueOf`` allowlist -- receiver is the class name), OR
      * a ``new StringBuilder(...)`` / ``new StringBuffer(...)`` construction
        (its own args are examined as a call, so the freshly built value carries
        no external string state of its own). Any other ``new X(...)`` is an
        unmodelled construct and is returned as a non-literal operand.

    Otherwise returns the receiver expression (a bare variable like ``sb`` /
    ``evil`` / ``query``, a field access, an unknown form) so the caller
    taint-checks it exactly like an argument: it is a non-literal operand and
    can never be proven safe.
    """
    g = leading_gap.strip()
    if not g:
        return None
    method = _TRAILING_IDENT_RE.search(g)
    if method is None:
        return None
    prefix = g[: method.start()].strip()
    if prefix.endswith("."):
        prefix = prefix[:-1].strip()
    if not prefix:
        return None  # bare call: no receiver
    if prefix == "String":
        return None  # allowlisted static receiver
    if re.match(r"^new(?:\s|$)", prefix):
        # A construction receiver stays SAFE-eligible ONLY for the modelled
        # string builders -- their own constructor args are examined as a call
        # below, so a freshly built value carries no external string state. Any
        # other `new X(...)` is an unmodelled construct whose `.method(...)`
        # semantics are unknown: return the whole receiver as a non-literal
        # operand so an all-literal `new Foo("a").append("b")` cannot read SAFE.
        cls = method.group().strip()
        # Only the BARE `new StringBuilder(...)` / `new StringBuffer(...)` shape
        # is allowlisted -- `prefix` is exactly `new` with no package qualifier.
        # A qualified name (`new com.evil.StringBuilder(...)`) leaves a non-empty
        # qualifier in `prefix`; we cannot tell the real `java.lang.StringBuilder`
        # from an attacker class whose simple name merely collides, so any
        # qualified form is treated as an unmodelled construct (never SAFE).
        if prefix.strip() == "new" and cls in ("StringBuilder", "StringBuffer"):
            return None
        return g
    return prefix


def _is_bare_call_receiver(leading_gap: str) -> bool:
    """True when ``leading_gap`` is a bare call NAME with no receiver before it
    (`currentQuery`, `buildQuery`, `format`) -- i.e. the case `_chain_receiver`
    treats as inert via its "bare call: no receiver" branch.

    `_chain_receiver` returns None for four shapes (empty gap, bare call,
    `String`, allowlisted `new`); this isolates the bare-call one so the caller
    can distinguish an opaque method-call receiver (whose unknown return value
    is NOT provably literal) from the genuinely-inert `String`/`new` forms.
    """
    g = leading_gap.strip()
    if not g:
        return False
    method = _TRAILING_IDENT_RE.search(g)
    if method is None:
        return False
    prefix = g[: method.start()].strip()
    if prefix.endswith("."):
        prefix = prefix[:-1].strip()
    return prefix == ""


def _chain_operand_candidates(text: str) -> tuple[list[str], bool]:
    """Candidate variable names from EVERY call in a dotted call chain --
    ``String.format(...)``, a ``StringBuilder``/``.append`` chain, or any mix,
    including calls this module has no special name for (``.substring(...)``,
    ``.concat(...)``, ``.replace(...)``, ...).

    This is the shared coverage guard: three rounds of review found the same
    fail-open shape three times over -- ``_format_operand_candidates`` reading
    only ``String.format(...)``'s own arguments, and ``_append_operand_candidates``
    reading only ``.append(...)`` sites, both let a SAFE verdict through
    whenever a *trailing* call they did not recognise (``.substring(evil)``
    after either idiom) was silently never examined. Precision was scoped to
    "the operands of the calls we went looking for"; the invariant that
    actually has to hold is "the operands of the WHOLE text, proven, not
    assumed". So this walks every real (quote-aware, `_CALL_RE`-matched) call
    in the text, whichever name it has, and tracks a `cursor` proving each
    one's args were read *and* that nothing between two calls -- or before the
    first, or after the last -- was left unexamined:

    * a gap that is pure chain navigation (a receiver/method name, dots,
      whitespace -- `_NAV_ONLY_RE`) is skipped, same as a receiver name always
      has been in this module;
    * any other gap (brackets, stray text, an unrecognised shape) is not
      trusted to be inert: it is scanned for identifiers exactly like a
      non-literal operand, and marks the result unresolved;
    * a call whose own argument list never balances (the unterminated-string
      shape from the previous two rounds) marks the rest of the text from
      that point on as unresolved rather than dropping it.

    SAFE is reachable through this function only when every character of the
    text was accounted for by a proven-literal operand or benign navigation --
    never by "the first call we recognised happened to be all-literal".
    """
    operands: list[str] = []
    unresolved = False
    cursor = 0
    n = len(text)
    calls = _call_open_parens_generic(text)
    for idx, open_paren in enumerate(calls):
        if open_paren < cursor:
            continue  # already inside a call span consumed above
        gap = text[cursor:open_paren]
        if not _NAV_ONLY_RE.match(gap):
            unresolved = True
            operands.append(gap)
        elif cursor == 0:
            # Only the leading gap carries the chain's *receiver*; every later
            # gap is `.method` navigation on the previous call's result and is
            # genuinely inert. An instance receiver's prior state IS part of
            # the resulting string, so a bare-variable receiver (`sb`, `evil`,
            # `query`) is a non-literal operand and must be taint-checked just
            # like an argument -- never exempted as mere navigation. Only a
            # `String.*` static call or a `new ...(...)` construction receiver
            # (whose own args are examined as a call below) stays SAFE-eligible.
            receiver = _chain_receiver(gap)
            if receiver is not None:
                operands.append(receiver)
            elif idx < len(calls) - 1 and _is_bare_call_receiver(gap):
                # A leading BARE call (`currentQuery()`, no receiver, not
                # `String` / `new StringBuilder`) whose result is CONSUMED by a
                # further chained call is an opaque, unmodelled value: its return
                # is not provably literal, so the whole chain can never read
                # SAFE. (A terminal bare call -- `format("%s", x)` -- keeps its
                # SAFE-eligibility; its own args are the operands examined below.)
                unresolved = True
        close_paren = _matching_close_paren(text, open_paren)
        if close_paren is None:
            unresolved = True
            cursor = n
            break
        # Split the call's argument list on TOP-LEVEL commas (quote/paren-aware
        # via `extract_all_args`) so each argument is tested individually by
        # the proven-literal check -- a multi-arg all-literal call
        # (`String.format("%d", 1)`) is a literal composition, not one opaque
        # comma-joined span.
        for arg in extract_all_args(text, open_paren):
            if arg:
                operands.append(arg)
        cursor = close_paren + 1
    tail = text[cursor:]
    if not _NAV_ONLY_RE.match(tail):
        unresolved = True
        operands.append(tail)
    names, operand_unresolved = _operand_candidates(operands)
    return names, unresolved or operand_unresolved


def _call_open_parens_generic(text: str) -> list[int]:
    """Indices of the ``(`` in every real, unquoted call: `_CALL_RE`, quote-aware.

    Same quote-tracking scan as `_append_open_parens`, generalised from the
    literal ``.append(`` to any bareword call -- deliberately so: it is what
    lets `_chain_operand_candidates` find a trailing ``.substring(evil)`` or
    ``.concat(...)`` the same way it finds the ``.append(``/``format(`` it
    was looking for, instead of needing a new special case per method name.
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
        match = _CALL_RE.match(text, i)
        if match:
            positions.append(match.end() - 1)
            i = match.end()
            continue
        i += 1
    return positions


def variable_names(arg_text: str) -> list[str]:
    """Identifiers from a top-level ``+`` operand, or a call chain otherwise --
    matching `assess`'s dispatch and its coverage guard.
    """
    s = arg_text.strip()
    parts = _split_plus(s)
    if len(parts) > 1:
        names, _unresolved = _operand_candidates(parts)
        return _dedup(names)
    names, _unresolved = _chain_operand_candidates(s)
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
        # operands beside it -- that suppression is the false-SAFE round 1
        # closed. Otherwise, `_chain_operand_candidates` is the shared
        # coverage guard closing round 3: it proves the operands it collects
        # account for the WHOLE text, not just the first call recognised.
        parts = _split_plus(s)
        if len(parts) > 1:
            names, unresolved = _operand_candidates(parts)
        else:
            names, unresolved = _chain_operand_candidates(s)
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        if names or unresolved:
            # a candidate variable (resolved or not) or an operand we could not
            # prove literal -> never read as safe
            return VERDICT_UNKNOWN
        # every operand is a proven literal/constant (e.g. `String.format("%d", 1)`)
        return VERDICT_SAFE
    # OPAQUE: candidates are only extracted from a call chain or a `+`
    # operand, so nothing is found in a bare identifier (neither of those)
    # even though the whole argument *is* one. Handle that shape directly: a
    # bare identifier can be checked against taint; any other opaque
    # expression (a call, field access, ...) has no name to check and must
    # fail safe rather than read as unconditionally SAFE.
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
