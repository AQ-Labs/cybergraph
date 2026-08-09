"""Analyzer contract and language dispatch registry.

Every language analyzer honours the same contract so its output maps onto the
shared security ontology regardless of language:

    analyze(path, repo_root, config) -> (nodes, edges, findings)

where analyzers are expected to emit, where applicable:

* a ``File`` node for the file, with a ``language`` property;
* ``Function`` nodes for definitions (keyed ``<relpath>::<name>``);
* ``Entrypoint`` nodes / ``EXPOSES_ENTRYPOINT`` edges for routes, handlers,
  webhooks, and other external inputs;
* ``GUARDS`` edges for authentication/authorization controls;
* ``SANITIZES`` edges for validation/sanitization barriers;
* ``REACHES_SINK`` edges (and a finding) for sensitive sinks;
* ``USES_SECRET`` edges for secret access;
* ``CALLS`` edges for call sites (resolved cross-file later).

Files with no specialized analyzer fall back gracefully to a bare ``File`` node
so the rest of the pipeline keeps working.
"""

from __future__ import annotations

from pathlib import Path

from cybergraph.config import CyberGraphConfig
from cybergraph.graph import Edge, Finding, Node

from .csharp import analyze_csharp_file
from .dockerfile import analyze_dockerfile_file
from .go import analyze_go_file
from .java import analyze_java_file
from .javascript import analyze_javascript_file
from .python import analyze_python_file
from .terraform import analyze_terraform_file

AnalyzerResult = tuple[list[Node], list[Edge], list[Finding]]

PYTHON_SUFFIXES = {".py"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
GO_SUFFIXES = {".go"}
JAVA_SUFFIXES = {".java"}
CSHARP_SUFFIXES = {".cs"}
TERRAFORM_SUFFIXES = {".tf"}
DOCKERFILE_SUFFIXES = {".dockerfile"}
DOCKERFILE_NAMES = {"Dockerfile"}

# Suffixes that have a dedicated security analyzer (everything else falls back).
ANALYZED_SUFFIXES = (
    PYTHON_SUFFIXES | JAVASCRIPT_SUFFIXES | GO_SUFFIXES | JAVA_SUFFIXES | CSHARP_SUFFIXES
    | TERRAFORM_SUFFIXES
)


#: Failures that belong to *one file* and must never end the walk over the rest.
#: Each is attributable to the file, bounded by it, and recoverable: the file is
#: reported as unreadable and the scan continues.
#:
#: * ``OSError`` -- an unreadable file, a dangling symlink, ``PermissionError``.
#: * ``ValueError`` -- ``ast.parse`` on a NUL-bearing string, and ``UnicodeDecodeError``,
#:   which is a ``ValueError`` subclass, when an analyzer decodes strictly.
#: * ``RecursionError`` -- nesting deeper than the interpreter's stack. The stack
#:   unwinds, so the next file starts from a clean state.
#:
#: Deliberately *not* contained, and deliberately not ``except Exception``:
#:
#: * ``MemoryError`` -- a condition of the process, not a property of this file.
#:   After it, what a later file's silence means is unknown, and a scan whose
#:   silence means nothing is worse than a scan that stopped.
#: * ``KeyboardInterrupt`` / ``SystemExit`` -- the operator asked to stop.
#: * everything else -- an analyzer bug. Turning ``AttributeError`` into a
#:   per-file "unreadable" note would render a detector regression across every
#:   file in the repository as routine housekeeping, which is the same
#:   silent-miss shape this containment exists to prevent. A crash is the honest
#:   report for a defect in the analyzer itself.
_CONTAINED_PER_FILE = (OSError, RecursionError, ValueError)

#: Emitted when a file defeated its analyzer. ``info`` because it is not a
#: vulnerability; present because "we could not read this" must be *stated*.
#: A file the scan silently skipped is indistinguishable from a clean one.
RULE_FILE_UNREADABLE = "CG-FILE-UNREADABLE"


def analyze_source_file(path: Path, repo_root: Path, config: CyberGraphConfig) -> AnalyzerResult:
    """Dispatch a source file to its language analyzer, or fall back to a File node.

    One malformed file must not abort a repository scan. Measured before this
    guard existed: a stray NUL byte, a ``.py`` saved as UTF-16 and a binary blob
    renamed ``.py`` each raised ``ValueError`` out of ``ast.parse``, through
    ``build_graph``, and took every other file's findings with them. The failure
    is contained here rather than in each analyzer so every language gets it,
    and so an analyzer that grows a new failure mode is covered by default.
    """
    try:
        return _dispatch(path, repo_root, config)
    except _CONTAINED_PER_FILE as exc:
        return _unreadable_file(path, repo_root, exc)


def _unreadable_file(path: Path, repo_root: Path, exc: BaseException) -> AnalyzerResult:
    rel = _relative(path, repo_root)
    return (
        [Node("File", rel, rel, rel, 1, 0)],
        [],
        [
            Finding(
                rule_id=RULE_FILE_UNREADABLE,
                severity="info",
                message="Source file could not be analyzed",
                file_path=rel,
                line_start=0,
                evidence=f"{type(exc).__name__}: {exc}",
            )
        ],
    )


def _relative(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def _dispatch(path: Path, repo_root: Path, config: CyberGraphConfig) -> AnalyzerResult:
    suffix = path.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return analyze_python_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            auth_markers=config.auth_markers,
            validation_markers=config.validation_markers,
            secret_markers=config.secret_markers,
        )
    if suffix in JAVASCRIPT_SUFFIXES:
        return analyze_javascript_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in GO_SUFFIXES:
        return analyze_go_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in JAVA_SUFFIXES:
        return analyze_java_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in CSHARP_SUFFIXES:
        return analyze_csharp_file(
            path,
            repo_root,
            custom_sinks=config.custom_sinks,
            secret_markers=config.secret_markers,
        )
    if suffix in TERRAFORM_SUFFIXES:
        return analyze_terraform_file(
            path,
            repo_root,
            secret_markers=config.secret_markers,
        )
    if suffix in DOCKERFILE_SUFFIXES or path.name in DOCKERFILE_NAMES:
        return analyze_dockerfile_file(
            path,
            repo_root,
            secret_markers=config.secret_markers,
        )
    return _fallback_file_node(path, repo_root)


def _fallback_file_node(path: Path, repo_root: Path) -> AnalyzerResult:
    rel = path.relative_to(repo_root).as_posix()
    line_count = len(path.read_text(errors="ignore").splitlines())
    return [Node("File", rel, rel, rel, 1, line_count)], [], []
