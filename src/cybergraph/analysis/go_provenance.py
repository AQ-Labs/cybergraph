"""Lightweight construction provenance for Go sink arguments.

No Go parser: a structural, statement-local classifier over the argument text,
fail-safe on anything it cannot read. It reuses the engine's vocabulary
(LITERAL/COMPOSED/OPAQUE and VERDICT_*) but is deliberately more conservative
than the Python predicates: because Go taint is weaker (intra-function,
line-based), only an all-literal/constant construction is SAFE. A construction
that contains a variable is UNSAFE when taint confirms it is user-controlled and
UNKNOWN otherwise -- never SAFE, and never a confident UNSAFE on an unresolved
variable.

Go has no template-literal interpolation; its idiom is ``fmt.Sprintf(fmt, ...)``,
so a Sprintf call is treated the way a JS template literal is treated: COMPOSED,
with its non-format arguments as candidate variables.
"""

from __future__ import annotations

import re

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import Sink

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_STRING_ONLY_RE = re.compile(r"""^\s*(?:'[^']*'|"[^"]*"|`[^`]*`)\s*$""")
_NUMERIC_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
# Go keywords that are also constant literals (booleans, the nil pointer) --
# proven literals, and also excluded from candidate variable names.
_GO_KEYWORDS = frozenset({"true", "false", "nil"})
_CONST_LITERAL_KEYWORDS = _GO_KEYWORDS


def extract_first_arg(source: str, open_paren: int) -> str | None:
    """Return the first top-level argument's source text, or None if unbalanced.

    String-aware (skips ()/,/quotes inside interpreted and raw string literals)
    so a ')' or ',' inside a literal does not end the argument early.
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
        elif c in "'\"`":
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

    Command-class sinks (`exec.Command`, `exec.CommandContext`) take argv, not
    a single string, so grading them on `extract_first_arg` alone only ever
    sees the program name -- for the Go shell idiom, the literal `"sh"` -- and
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
        elif c in "'\"`":
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
    if s.startswith("fmt.Sprintf(") or len(_split_plus(s)) > 1:
        return COMPOSED
    return OPAQUE


def _is_proven_literal_operand(operand: str) -> bool:
    """True only for a construction that is positively known to be constant.

    A string literal (interpreted ``"..."`` or raw `` `...` ``), or a
    numeric/boolean/nil constant. Anything else -- a bare identifier, a
    parenthesized expression, a bracketed expression, a call, a selector -- is
    NOT proven literal, even if it happens to contain no scannable identifier:
    absence of a name must never be read as proof of literal-ness.
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
            if ident not in _GO_KEYWORDS:
                names.append(ident)
    return names, unresolved


def _plus_operand_candidates(arg_text: str) -> tuple[list[str], bool]:
    """Candidate variable names from non-literal top-level ``+`` operands."""
    return _operand_candidates(_split_plus(arg_text))


def _sprintf_operand_candidates(sprintf_text: str) -> tuple[list[str], bool]:
    """Candidate variable names from ALL of a ``fmt.Sprintf(...)`` call's arguments.

    Unlike a JS template literal, whose leading piece is always a literal
    fragment of the source text, Go's format argument is a normal runtime
    value: ``fmt.Sprintf(userQuery)`` and ``fmt.Sprintf("SELECT * FROM " +
    tbl, "x")`` both carry a non-literal format. So every argument -- format
    included -- is assessed with the same positive-literal-proof logic; a
    format that genuinely is a string literal is a proven literal and is
    skipped by `_is_proven_literal_operand` on its own, with no special-casing
    needed here.
    """
    args = _split_call_args(sprintf_text)
    return _operand_candidates(args)


def variable_names(arg_text: str) -> list[str]:
    """Identifiers from a fmt.Sprintf argument list or a non-literal + operand."""
    s = arg_text.strip()
    if s.startswith("fmt.Sprintf(") and s.endswith(")"):
        names, _unresolved = _sprintf_operand_candidates(s)
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
        elif c in "'\"`":
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


def _split_call_args(s: str) -> list[str]:
    """Top-level, comma-separated arguments of the first ``(...)`` call in s.

    Mirrors ``extract_first_arg``'s string/paren-aware scan, but returns every
    top-level argument instead of stopping at the first. Used to split
    ``fmt.Sprintf(...)``'s argument list.
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
        elif c in "'\"`":
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
    return args  # unbalanced -> caller treats as best-effort partial list


def assess(sink: Sink, arg_text: str | None, tainted_names: set[str]) -> str:
    """Verdict for a Go sink call. Only an all-literal/constant construction is SAFE."""
    if arg_text is None:
        return VERDICT_UNKNOWN
    construction = classify(arg_text)
    if construction == LITERAL:
        return VERDICT_SAFE
    if construction == COMPOSED:
        s = arg_text.strip()
        if s.startswith("fmt.Sprintf(") and s.endswith(")"):
            names, unresolved = _sprintf_operand_candidates(s)
        else:
            names, unresolved = _plus_operand_candidates(arg_text)
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        if names or unresolved:
            # a candidate variable (resolved or not) or an operand we could not
            # prove literal -> never read as safe
            return VERDICT_UNKNOWN
        # every operand is a proven literal/constant (e.g. `fmt.Sprintf("%d", 1)`)
        return VERDICT_SAFE
    # OPAQUE: candidates are only extracted from a `fmt.Sprintf(...)` call or a
    # `+` operand, so nothing is found in a bare identifier (no Sprintf, no `+`)
    # even though the whole argument *is* one. Handle that shape directly: a
    # bare identifier can be checked against taint; any other opaque expression
    # (a call, selector, ...) has no name to check and must fail safe rather
    # than read as unconditionally SAFE.
    s = arg_text.strip()
    match = _IDENT_RE.fullmatch(s)
    if match and match.group(0) not in _GO_KEYWORDS and match.group(0) in tainted_names:
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN


def assess_command(sink: Sink, args: list[str] | None, tainted_names: set[str]) -> str:
    """Verdict for a Go command sink (`exec.Command`/`exec.CommandContext`) over ALL arguments.

    `assess` grades a sink on its first argument alone, which is right for a
    single SQL/path string but wrong for argv: it would see only the program
    name and miss a tainted argument anywhere else in the call. This assesses
    the whole argument list instead, reusing `_operand_candidates` /
    `_is_proven_literal_operand` so the same positive-literal-proof invariant
    holds -- a non-literal argument with no scannable identifier is
    unresolved, never silently SAFE.

    Verdict rule, fail-safe throughout:
    - no arguments (unreadable call) -> UNKNOWN.
    - every argument is a proven literal/constant -> SAFE.
    - the shell form -- argv[0] is a shell (`sh`/`bash`/`/bin/sh`/`/bin/bash`)
      with a `-c` argument present -- and some argument is not a proven
      literal -> UNSAFE if a candidate name is taint-confirmed, else UNKNOWN.
    - otherwise (argv form, or any other shape) and some argument is not a
      proven literal -> UNSAFE if a candidate name is taint-confirmed, else
      UNKNOWN.

    The shell and non-shell branches compute identically: taint confirmation
    over every argument's candidate names is what decides UNSAFE vs. UNKNOWN
    in both, because this phase does not yet distinguish argument-injection
    severity by argv position. In neither branch is a non-literal argument
    ever read as SAFE, which is the false-SAFE this function exists to close.
    """
    if not args:
        return VERDICT_UNKNOWN
    if all(_is_proven_literal_operand(a) for a in args):
        return VERDICT_SAFE
    names, _unresolved = _operand_candidates(args)
    if any(n in tainted_names for n in names):
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN
