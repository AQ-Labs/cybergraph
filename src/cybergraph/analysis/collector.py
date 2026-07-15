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
}
SUPPORTED_FILENAMES = {"package.json", "requirements.txt", "pyproject.toml", "Dockerfile"}


def iter_source_files(repo_root: Path, ignored_paths: tuple[str, ...] = ()) -> list[Path]:
    files: list[Path] = []
    repo_root = repo_root.resolve()
    for path in repo_root.rglob("*"):
        rel_path = path.relative_to(repo_root)
        rel_parts = rel_path.parts
        if any(part in DEFAULT_EXCLUDES for part in rel_parts):
            continue
        rel = rel_path.as_posix()
        ignored = tuple(pattern.replace("\\", "/").rstrip("/") for pattern in ignored_paths)
        if any(fnmatch(rel, pattern) or rel.startswith(pattern + "/") for pattern in ignored):
            continue
        if path.is_file() and (
            path.suffix.lower() in SUPPORTED_SUFFIXES or path.name in SUPPORTED_FILENAMES
        ):
            files.append(path)
    return sorted(files)
