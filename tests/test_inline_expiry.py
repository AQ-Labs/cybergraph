"""Inline `# cybergraph: ignore ... expires=YYYY-MM-DD` expiry (fail-open, injectable `today`).

An inline marker may carry an `expires=` token, same accountable-suppression
spirit as the config-level `[[suppressions]]` entries: a marker whose expiry
has passed, or is malformed, must not suppress -- silently expired markers are
worse than none, because they read as "reviewed" while hiding a live finding.
"""

from __future__ import annotations

from datetime import date

from cybergraph.suppressions import is_inline_suppressed

TODAY = date(2026, 6, 1)


def test_expired_inline_marker_does_not_suppress():
    lines = ["exec(query)  # cybergraph: ignore CG-SQL-EXEC expires=2026-01-01"]
    assert not is_inline_suppressed(lines, 1, "CG-SQL-EXEC", today=TODAY)


def test_unexpired_inline_marker_suppresses():
    lines = ["exec(query)  # cybergraph: ignore CG-SQL-EXEC expires=2026-12-31"]
    assert is_inline_suppressed(lines, 1, "CG-SQL-EXEC", today=TODAY)


def test_bare_marker_without_expires_still_suppresses():
    lines = ["exec(query)  # cybergraph: ignore CG-SQL-EXEC"]
    assert is_inline_suppressed(lines, 1, "CG-SQL-EXEC", today=TODAY)


def test_malformed_expires_does_not_suppress():
    lines = ["exec(query)  # cybergraph: ignore CG-SQL-EXEC expires=nope"]
    assert not is_inline_suppressed(lines, 1, "CG-SQL-EXEC", today=TODAY)
