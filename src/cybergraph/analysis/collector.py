"""Repository file collection."""

from __future__ import annotations

from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git", ".venv", "venv", "env", "node_modules", "dist", "build", "__pycache__",
    ".cybergraph", ".pytest_cache", ".ruff_cache",
}

SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php"}


def iter_source_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo_root.rglob("*"):
        if any(part in DEFAULT_EXCLUDES for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            files.append(path)
    return sorted(files)
