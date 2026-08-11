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
# a template literal with no interpolation hole
_TEMPLATE_NO_INTERP_RE = re.compile(r"^\s*`[^`]*`\s*$")
_INTERP_RE = re.compile(r"\$\{([^}]*)\}")
_JS_KEYWORDS = {"true", "false", "null", "undefined", "this"}


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


def variable_names(arg_text: str) -> list[str]:
    """Identifiers introduced by ${...} interpolation or a + operand, minus literals."""
    names: list[str] = []
    for hole in _INTERP_RE.findall(arg_text):
        m = _IDENT_RE.search(hole)
        if m and m.group(0) not in _JS_KEYWORDS:
            names.append(m.group(0))
    if "+" in arg_text:
        # operands that are not string literals
        for part in _split_plus(arg_text):
            p = part.strip()
            if p and p[0] not in "'\"`":
                m = _IDENT_RE.match(p)
                if m and m.group(0) not in _JS_KEYWORDS and not p[0].isdigit():
                    names.append(m.group(0))
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
        if not names:
            # composed of only literals (e.g. `'a' + 'b'`) -> safe
            return VERDICT_SAFE
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        return VERDICT_UNKNOWN
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
