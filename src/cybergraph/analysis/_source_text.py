"""Neutralise comments and string literals before markers are matched.

The four non-Python analysers (Go, JavaScript, Java, C#) decide whether a line
*reads user input* by testing whether a taint marker (``.query(``, ``req.body``,
``getparameter`` ...) appears in the line. Historically that test ran against the
raw line, so a marker sitting inside a comment or a string literal counted the
same as a genuine request read::

    host := "see .body docs"   // Go: the string contains ".body" -> a taint source

This module produces a *code view* of a source file: a list of lines, aligned
one-to-one with ``source.splitlines()``, in which every comment and every string
literal has had its text replaced by spaces. The delimiters and the literal text
are blanked; line-boundary characters are preserved verbatim so the returned list
stays aligned with the original line numbering. A marker that only ever appeared
inside a comment or a string simply is not present in the code view, while a
genuine ``req.query`` on real code survives untouched -- including when it shares
a line with a string that happens to contain a marker word.

**Polarity.** The marker test proves *danger*: a source it fails to see is a
silent miss, the worst outcome. Every judgement here therefore fails toward
*keeping text as code* (a marker still seen, a source still flagged), never toward
dropping a real source:

* An unterminated block comment or multi-line string runs to end-of-file -- the
  same span the language itself would treat as unterminated.
* Interpolation holes are kept **as code**: ``${req.query}`` in a JS template and
  ``{Request.Query[x]}`` in a C# interpolated string carry real, taintable
  expressions, so their contents are preserved rather than blanked. A nested
  string inside an interpolation hole is left as code too -- a false positive at
  worst, never a missed source.
* Constructs not modelled (a JS regex literal, a C# raw triple-quoted string) are
  left entirely as code, so any marker inside them is still seen.

Stdlib only, by project rule (``dependencies = []``): a hand-written per-language
scanner, no parser dependency.
"""

from __future__ import annotations

from dataclasses import dataclass

# Characters ``str.splitlines`` treats as line boundaries. They are preserved
# verbatim wherever they occur (even inside a blanked span) so the code view
# splits into exactly the same lines as the original source.
_LINE_BOUNDARIES = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
# Real newlines end a single-line string; the exotic boundaries above do not.
_NEWLINES = frozenset("\n\r")


def _blank(ch: str) -> str:
    """Replace a neutralised character with a space, keeping line boundaries."""
    return ch if ch in _LINE_BOUNDARIES else " "


@dataclass(frozen=True)
class _StringKind:
    """One flavour of string literal and how to find where it ends."""

    open: str
    close: str
    escape: bool = False  # backslash escapes the next character (incl. the close)
    multiline: bool = False  # a real newline does not terminate this string
    double_close_escapes: bool = False  # a doubled close delimiter is a literal, not the end
    interp_open: str | None = None  # token that opens an interpolation hole
    interp_double_escapes: bool = False  # a doubled interp-open token is a literal brace


@dataclass(frozen=True)
class _Syntax:
    line_comments: tuple[str, ...]
    block_comments: tuple[tuple[str, str], ...]
    # Tried in order at each position, so longer / more specific openers first.
    strings: tuple[_StringKind, ...]


_DQ = _StringKind('"', '"', escape=True)
_SQ = _StringKind("'", "'", escape=True)

_SYNTAX: dict[str, _Syntax] = {
    "go": _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        strings=(
            _StringKind("`", "`", multiline=True),  # raw string: no escapes
            _DQ,
            _SQ,  # rune literal
        ),
    ),
    "javascript": _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        strings=(
            _StringKind("`", "`", escape=True, multiline=True, interp_open="${"),
            _DQ,
            _SQ,
        ),
    ),
    "java": _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        strings=(
            _StringKind('"""', '"""', escape=True, multiline=True),  # text block
            _DQ,
            _SQ,  # char literal
        ),
    ),
    "csharp": _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        strings=(
            # interpolated verbatim: no backslash escapes, "" is a literal quote,
            # spans lines, {..} holes with {{ as a literal brace.
            _StringKind(
                '$@"', '"', multiline=True, double_close_escapes=True,
                interp_open="{", interp_double_escapes=True,
            ),
            _StringKind(
                '@$"', '"', multiline=True, double_close_escapes=True,
                interp_open="{", interp_double_escapes=True,
            ),
            _StringKind('@"', '"', multiline=True, double_close_escapes=True),  # verbatim
            _StringKind(
                '$"', '"', escape=True, interp_open="{", interp_double_escapes=True,
            ),  # interpolated
            _DQ,
            _SQ,  # char literal
        ),
    ),
}


def strip_code(source: str, language: str) -> list[str]:
    """Return ``source`` split into lines with comments and strings blanked.

    The result is aligned one-to-one with ``source.splitlines()``. ``language``
    is one of ``"go"``, ``"javascript"``, ``"java"``, ``"csharp"``; an unknown
    language returns the source split unchanged (fail toward keeping code).
    """
    syntax = _SYNTAX.get(language)
    if syntax is None:
        return source.splitlines()

    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        nxt = _consume_comment(source, i, syntax, out)
        if nxt is not None:
            i = nxt
            continue
        kind = _string_at(source, i, syntax)
        if kind is not None:
            i = _consume_string(source, i, kind, out)
            continue
        out.append(source[i])
        i += 1
    return "".join(out).splitlines()


def _consume_comment(source: str, i: int, syntax: _Syntax, out: list[str]) -> int | None:
    n = len(source)
    for opener in syntax.line_comments:
        if source.startswith(opener, i):
            j = i
            while j < n and source[j] not in _NEWLINES:
                out.append(_blank(source[j]))
                j += 1
            return j
    for opener, closer in syntax.block_comments:
        if source.startswith(opener, i):
            end = source.find(closer, i + len(opener))
            end = n if end == -1 else end + len(closer)
            for j in range(i, end):
                out.append(_blank(source[j]))
            return end
    return None


def _string_at(source: str, i: int, syntax: _Syntax) -> _StringKind | None:
    for kind in syntax.strings:
        if source.startswith(kind.open, i):
            return kind
    return None


def _consume_string(source: str, i: int, kind: _StringKind, out: list[str]) -> int:
    n = len(source)
    for j in range(i, i + len(kind.open)):
        out.append(_blank(source[j]))
    i += len(kind.open)

    while i < n:
        ch = source[i]

        if ch in _NEWLINES:
            out.append(ch)
            i += 1
            if not kind.multiline:
                return i  # a real newline ends a single-line string literal
            continue

        if kind.escape and ch == "\\":
            out.append(" ")
            i += 1
            if i < n:  # blank the escaped character too (preserving any boundary)
                out.append(_blank(source[i]))
                i += 1
            continue

        if kind.double_close_escapes and source.startswith(kind.close * 2, i):
            out.append(" ")
            out.append(" ")
            i += 2
            continue

        if kind.interp_open is not None:
            if kind.interp_double_escapes and source.startswith(kind.interp_open * 2, i):
                out.append(_blank(source[i]))
                out.append(_blank(source[i + 1]))
                i += 2
                continue
            if source.startswith(kind.interp_open, i):
                i = _consume_interpolation(source, i, kind, out)
                continue

        if source.startswith(kind.close, i):
            for j in range(i, i + len(kind.close)):
                out.append(_blank(source[j]))
            return i + len(kind.close)

        out.append(_blank(ch))
        i += 1

    return n  # unterminated string: consumed to end of file


def _consume_interpolation(source: str, i: int, kind: _StringKind, out: list[str]) -> int:
    """Copy an interpolation hole ``${ ... }`` / ``{ ... }`` through as live code.

    The opening token is blanked; the expression is emitted verbatim so a real
    ``req.query`` inside it still reads as a source. Brace depth tracks the end;
    a nested string inside the hole is left as code, which can only ever add a
    marker, never drop one.
    """
    n = len(source)
    assert kind.interp_open is not None
    for j in range(i, i + len(kind.interp_open)):
        out.append(_blank(source[j]))
    i += len(kind.interp_open)
    depth = 1
    while i < n and depth > 0:
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append(_blank(ch))
                return i + 1
        out.append(ch)  # expression text is live code
        i += 1
    return i
