"""Analysis package exports."""

from .collector import iter_source_files
from .csharp import analyze_csharp_file
from .dependencies import analyze_dependency_manifest, is_dependency_manifest
from .dockerfile import analyze_dockerfile_file
from .go import analyze_go_file
from .java import analyze_java_file
from .javascript import analyze_javascript_file
from .python import analyze_python_file
from .registry import analyze_source_file
from .terraform import analyze_terraform_file

__all__ = [
    "analyze_csharp_file",
    "analyze_dependency_manifest",
    "analyze_dockerfile_file",
    "analyze_go_file",
    "analyze_java_file",
    "analyze_javascript_file",
    "analyze_python_file",
    "analyze_source_file",
    "analyze_terraform_file",
    "is_dependency_manifest",
    "iter_source_files",
]
