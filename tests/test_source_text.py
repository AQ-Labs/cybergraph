"""Unit tests for the comment/string stripper shared by the non-Python analysers."""

from __future__ import annotations

from cybergraph.analysis._source_text import strip_code


def _joined(source: str, lang: str) -> str:
    """Lowercased code view, joined, for substring assertions on markers."""
    return "\n".join(strip_code(source, lang)).lower()


def test_strip_preserves_line_count_and_alignment() -> None:
    src = "a\nb // c\n/* d\ne */ f\n"
    stripped = strip_code(src, "go")
    assert len(stripped) == len(src.splitlines())
    assert stripped[0] == "a"
    assert stripped[3].endswith("f")


# --- Go -------------------------------------------------------------------

def test_go_marker_in_string_and_comment_is_removed() -> None:
    src = 'host := "see .body docs"  // url.query note\nraw := `x .query( y`'
    out = _joined(src, "go")
    assert ".body" not in out
    assert "url.query" not in out
    assert ".query(" not in out


def test_go_genuine_source_survives() -> None:
    out = _joined('name := r.URL.Query().Get("h")', "go")
    assert "url.query" in out


def test_go_mixed_source_and_string_marker() -> None:
    # A real read on the same line as a string containing a marker word.
    out = _joined('name := r.URL.Query().Get("see .body docs")', "go")
    assert "url.query" in out


# --- JavaScript -----------------------------------------------------------

def test_js_marker_in_string_and_comment_is_removed() -> None:
    src = 'const h = "see req.body text";  // req.query note\nconst t = `plain req.params`;'
    out = _joined(src, "javascript")
    assert "req.body" not in out
    assert "req.query" not in out
    assert "req.params" not in out


def test_js_genuine_source_survives() -> None:
    assert "req.query" in _joined("const id = req.query.id;", "javascript")


def test_js_template_interpolation_is_kept_as_code() -> None:
    # The hole carries a real source and must not be blanked (no silent miss).
    assert "req.query" in _joined("const u = `id=${req.query.id}`;", "javascript")


def test_js_mixed_source_and_string_marker() -> None:
    assert "req.query" in _joined('const x = req.query.id + "see req.body here";', "javascript")


# --- Java -----------------------------------------------------------------

def test_java_marker_in_string_comment_and_textblock_is_removed() -> None:
    src = (
        'String a = "getParameter here";  // @RequestParam note\n'
        'String b = """\ngetParameter inside block\n""";'
    )
    out = _joined(src, "java")
    assert "getparameter" not in out
    assert "@requestparam" not in out


def test_java_genuine_source_survives() -> None:
    assert "getparameter" in _joined('String p = request.getParameter("x");', "java")


def test_java_mixed_source_and_string_marker() -> None:
    out = _joined('String p = request.getParameter("getParameter docs");', "java")
    assert "getparameter" in out


# --- C# -------------------------------------------------------------------

def test_csharp_marker_in_string_verbatim_and_comment_is_removed() -> None:
    src = (
        'var a = "Request.Query text";  // Request.Form note\n'
        'var b = @"see Request.Headers here";'
    )
    out = _joined(src, "csharp")
    assert "request.query" not in out
    assert "request.form" not in out
    assert "request.headers" not in out


def test_csharp_genuine_source_survives() -> None:
    assert "request.query" in _joined('var id = Request.Query["id"];', "csharp")


def test_csharp_interpolation_hole_is_kept_as_code() -> None:
    assert "request.query" in _joined('var u = $"id={Request.Query}";', "csharp")


def test_csharp_mixed_source_and_string_marker() -> None:
    out = _joined('var id = Request.Query["see Request.Form here"];', "csharp")
    assert "request.query" in out


def test_unknown_language_returns_source_unchanged() -> None:
    src = 'x = "anything"\n'
    assert strip_code(src, "ruby") == src.splitlines()
