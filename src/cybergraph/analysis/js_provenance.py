"""Lightweight construction provenance for JavaScript/TypeScript sink arguments.

No JS parser: a structural, statement-local classifier over the argument text,
fail-safe on anything it cannot read. It reuses the engine's vocabulary
(LITERAL/COMPOSED/OPAQUE and VERDICT_*) but is deliberately more conservative
than the Python predicates: because JS taint is weaker (intra-function,
line-based), only an all-literal/constant construction is SAFE. A construction
that contains a variable is UNSAFE when taint confirms it is user-controlled and
UNKNOWN otherwise -- never SAFE, and never a confident UNSAFE on an unresolved
variable.
"""

from __future__ import annotations

import re

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import Sink

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_STRING_ONLY_RE = re.compile(r"""^\s*(?:'[^']*'|"[^"]*"|`[^`]*`)\s*$""")
_NUMERIC_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_INTERP_RE = re.compile(r"\$\{([^}]*)\}")
_JS_KEYWORDS = {"true", "false", "null", "undefined", "this"}
# numeric/boolean/null constants -- proven literals even though "true"/"null" are
# also excluded from candidate variable names as JS keywords
_CONST_LITERAL_KEYWORDS = {"true", "false", "null"}


def extract_first_arg(source: str, open_paren: int) -> str | None:
    """Return the first top-level argument's source text, or None if unbalanced.

    String-aware (skips ()/,/quotes inside string and template literals) so a
    ')' or ',' inside a literal does not end the argument early.
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


def classify(arg_text: str) -> str:
    s = arg_text.strip()
    if _STRING_ONLY_RE.match(s) and "${" not in s:
        return LITERAL
    if s.startswith("`") and "${" in s:
        return COMPOSED
    if len(_split_plus(s)) > 1:
        return COMPOSED
    return OPAQUE


def _is_proven_literal_operand(operand: str) -> bool:
    """True only for a construction that is positively known to be constant.

    A string/template literal with no ``${}`` hole, or a numeric/boolean/null
    constant. Anything else -- a bare identifier, a parenthesized expression, a
    bracketed expression, a ternary, a call, member access -- is NOT proven
    literal, even if it happens to contain no scannable identifier: absence of
    a name must never be read as proof of literal-ness.
    """
    s = operand.strip()
    if not s:
        return False
    if _STRING_ONLY_RE.match(s) and "${" not in s:
        return True
    if _NUMERIC_RE.match(s):
        return True
    if s in _CONST_LITERAL_KEYWORDS:
        return True
    return False


def _plus_operand_candidates(arg_text: str) -> tuple[list[str], bool]:
    """Candidate variable names from non-literal top-level ``+`` operands.

    Also returns whether any operand is "unresolved": not a proven literal and
    yet contains no identifier at all (e.g. `(1 + 1)` as an operand) -- such an
    operand must never be silently treated as safe just because it has no name
    to check.
    """
    names: list[str] = []
    unresolved = False
    for part in _split_plus(arg_text):
        p = part.strip()
        if not p or _is_proven_literal_operand(p):
            continue
        idents = _IDENT_RE.findall(p)
        if not idents:
            unresolved = True
            continue
        for ident in idents:
            if ident not in _JS_KEYWORDS:
                names.append(ident)
    return names, unresolved


def variable_names(arg_text: str) -> list[str]:
    """Identifiers introduced by ${...} interpolation or a non-literal + operand."""
    names: list[str] = []
    for hole in _INTERP_RE.findall(arg_text):
        m = _IDENT_RE.search(hole)
        if m and m.group(0) not in _JS_KEYWORDS:
            names.append(m.group(0))
    if "+" in arg_text:
        plus_names, _unresolved = _plus_operand_candidates(arg_text)
        names.extend(plus_names)
    # de-dup, preserve order
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


def assess(sink: Sink, arg_text: str | None, tainted_names: set[str]) -> str:
    """Verdict for a JS sink call. Only an all-literal/constant construction is SAFE."""
    if arg_text is None:
        return VERDICT_UNKNOWN
    construction = classify(arg_text)
    if construction == LITERAL:
        return VERDICT_SAFE
    if construction == COMPOSED:
        names = variable_names(arg_text)
        unresolved = False
        if "+" in arg_text:
            _plus_names, unresolved = _plus_operand_candidates(arg_text)
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        if names or unresolved:
            # a candidate variable (resolved or not) or an operand we could not
            # prove literal -> never read as safe
            return VERDICT_UNKNOWN
        # every operand is a proven literal/constant (e.g. `'a' + 'b'`) -> safe
        return VERDICT_SAFE
    # OPAQUE: `variable_names` only extracts identifiers introduced by `${...}`
    # interpolation or a `+` operand, so it finds nothing in a bare identifier
    # (no template, no `+`) even though the whole argument *is* one. Handle
    # that shape directly: a bare identifier can be checked against taint; any
    # other opaque expression (a call, member access, ...) has no name to
    # check and must fail safe rather than read as unconditionally SAFE.
    s = arg_text.strip()
    match = _IDENT_RE.fullmatch(s)
    if match and match.group(0) not in _JS_KEYWORDS and match.group(0) in tainted_names:
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN
