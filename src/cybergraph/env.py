"""Minimal .env loader (no dependency). Sets only vars absent from the environment."""

from __future__ import annotations

import os
from pathlib import Path


def _strip_inline_comment(value: str) -> str:
    """Truncate ``value`` at a ``#`` that starts a comment.

    Only a ``#`` preceded by whitespace and outside single/double quotes is
    treated as a comment marker, so ``K="a#b"`` keeps its literal ``#``.
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(value):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif (
            ch == "#"
            and not in_single
            and not in_double
            and i > 0
            and value[i - 1] in " \t"
        ):
            return value[:i]
    return value


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = _strip_inline_comment(value)
        value = value.strip().strip('"').strip("'")
        if key:
            out[key] = value
    return out


def load_dotenv(repo_root: Path | None = None) -> int:
    """Load ``.env`` from ``repo_root`` and cwd; set only keys not already set.

    Returns the number of environment variables newly set. Never overrides an
    existing environment value; non-fatal on any read/parse error."""
    candidates = []
    if repo_root is not None:
        candidates.append(Path(repo_root) / ".env")
    candidates.append(Path.cwd() / ".env")

    set_count = 0
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        try:
            pairs = _parse(resolved.read_text(encoding="utf-8-sig"))
        except OSError:
            continue
        for key, value in pairs.items():
            if key not in os.environ:
                os.environ[key] = value
                set_count += 1
    return set_count
