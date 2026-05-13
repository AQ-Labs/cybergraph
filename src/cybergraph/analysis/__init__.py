"""Analysis package exports."""

from .collector import iter_source_files
from .dependencies import analyze_dependency_manifest, is_dependency_manifest
from .javascript import analyze_javascript_file
from .python import analyze_python_file

__all__ = [
    "analyze_dependency_manifest",
    "analyze_javascript_file",
    "analyze_python_file",
    "is_dependency_manifest",
    "iter_source_files",
]
