"""Which changed files were actually analyzed.

Zero findings has two very different causes: the analyzer looked and found
nothing, or it never looked. Without this module they are indistinguishable, and
a Python file with a syntax error reads as clean.

``analyze_python_file`` already records a ``PY-SYNTAX`` finding when a file fails
to parse; nothing consumed it. A changed source file counts as ``analyzed`` only
when the graph holds a ``File`` node for it and no parse failure is recorded
against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.capability import SOURCE_GLOBS, VERIFIED_GLOBS

STATUS_ANALYZED = "analyzed"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_MISSING = "missing"

_PARSE_FAILURE_RULES = ("PY-SYNTAX",)


@dataclass(frozen=True)
class FileCoverage:
    path: str
    status: str
    reason: str = ""


def assess_coverage(
    repo_root: Path, changed_files: tuple[str, ...]
) -> tuple[FileCoverage, ...]:
    """Report analysis status for every changed *source* file."""
    repo_root = Path(repo_root).resolve()
    sources = tuple(
        file for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
    )
    if not sources:
        return ()

    store = GraphStore.open_for_repo(repo_root)
    try:
        known = {
            row["key"]
            for row in store.conn.execute("SELECT key FROM nodes WHERE kind = 'File'")
        }
        failed = {
            row["file_path"]
            for row in store.conn.execute(
                "SELECT file_path FROM findings WHERE rule_id IN "
                f"({','.join('?' for _ in _PARSE_FAILURE_RULES)})",
                _PARSE_FAILURE_RULES,
            )
        }
    finally:
        store.close()

    results: list[FileCoverage] = []
    for file in sources:
        if file in failed:
            results.append(FileCoverage(file, STATUS_FAILED, "the file could not be read"))
        elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS):
            results.append(
                FileCoverage(file, STATUS_UNSUPPORTED, "no analyzer for this language yet")
            )
        elif file in known:
            results.append(FileCoverage(file, STATUS_ANALYZED))
        elif not (repo_root / file).exists():
            results.append(FileCoverage(file, STATUS_MISSING, "deleted in this change"))
        else:
            results.append(
                FileCoverage(file, STATUS_FAILED, "the file was not analyzed")
            )
    return tuple(results)
