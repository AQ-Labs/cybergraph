"""Repository file collection."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".cybergraph",
    ".pytest_cache",
    ".ruff_cache",
}

SUPPORTED_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".cs",
    ".rb",
    ".php",
    ".tf",
    ".dockerfile",
    ".rules",
}
SUPPORTED_FILENAMES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Dockerfile",
    "firebase.json",
}


def is_ignored_path(rel_path: str, ignored_paths: tuple[str, ...] = ()) -> bool:
    """Whether a repo-relative path is excluded by ``[ignore] paths``.

    Exported so callers that need to *describe* the exclusion -- a PR review
    naming the changed files the analysis never read -- ask the same predicate
    the collector applies, instead of reimplementing the glob semantics and
    drifting from it.
    """
    rel = rel_path.replace("\\", "/")
    for pattern in ignored_paths:
        cleaned = pattern.replace("\\", "/").rstrip("/")
        if not cleaned:
            continue
        if fnmatch(rel, cleaned) or rel.startswith(cleaned + "/"):
            return True
    return False


def is_supabase_sql(path: Path) -> bool:
    return path.suffix.lower() == ".sql" and any(
        part.lower() == "supabase" for part in path.parts
    )


def is_bucket_policy(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".json") and (
        "bucket-policy" in name or "bucket_policy" in name or name.endswith(".iam.json")
    )


def is_supported_source(path: Path) -> bool:
    """Whether the analyzers would read this file at all, ignoring config."""
    return (
        path.suffix.lower() in SUPPORTED_SUFFIXES
        or path.name in SUPPORTED_FILENAMES
        or is_supabase_sql(path)
        or is_bucket_policy(path)
    )


def iter_source_files(repo_root: Path, ignored_paths: tuple[str, ...] = ()) -> list[Path]:
    files: list[Path] = []
    repo_root = repo_root.resolve()
    for path in repo_root.rglob("*"):
        rel_path = path.relative_to(repo_root)
        rel_parts = rel_path.parts
        if any(part in DEFAULT_EXCLUDES for part in rel_parts):
            continue
        if is_ignored_path(rel_path.as_posix(), tuple(ignored_paths)):
            continue
        if path.is_file() and is_supported_source(path):
            files.append(path)
    return sorted(files)
