"""Repository file collection."""

from __future__ import annotations

from pathlib import Path
from fnmatch import fnmatch

DEFAULT_EXCLUDES = {
    ".git", ".venv", "venv", "env", "node_modules", "dist", "build", "__pycache__",
    ".cybergraph", ".pytest_cache", ".ruff_cache",
}

SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".rb", ".php"}
SUPPORTED_FILENAMES = {"package.json", "requirements.txt", "pyproject.toml"}


def iter_source_files(repo_root: Path, ignored_paths: tuple[str, ...] = ()) -> list[Path]:
    files: list[Path] = []
    for path in repo_root.rglob("*"):
        if any(part in DEFAULT_EXCLUDES for part in path.parts):
            continue
        rel = path.relative_to(repo_root).as_posix()
        if any(fnmatch(rel, pattern) or rel.startswith(pattern.rstrip("/") + "/") for pattern in ignored_paths):
            continue
        if path.is_file() and (path.suffix.lower() in SUPPORTED_SUFFIXES or path.name in SUPPORTED_FILENAMES):
            files.append(path)
    return sorted(files)
