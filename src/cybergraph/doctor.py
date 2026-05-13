"""CyberGraph environment diagnostics."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cybergraph.config import CONFIG_FILE, load_config
from cybergraph.graph import GraphStore


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_doctor(repo_root: Path) -> list[DoctorCheck]:
    repo_root = repo_root.resolve()
    checks = [
        _check_repo_exists(repo_root),
        _check_git(repo_root),
        _check_config(repo_root),
        _check_graph(repo_root),
        _check_workflow(repo_root),
    ]
    return checks


def format_doctor(checks: list[DoctorCheck]) -> str:
    lines = ["CyberGraph doctor:"]
    for check in checks:
        mark = "OK" if check.ok else "WARN"
        lines.append(f"[{mark}] {check.name}: {check.detail}")
    if all(check.ok for check in checks):
        lines.append("")
        lines.append("Everything looks ready.")
    else:
        lines.append("")
        lines.append("Suggested start:")
        lines.append("  cybergraph init .")
        lines.append("  cybergraph build .")
    return "\n".join(lines)


def _check_repo_exists(repo_root: Path) -> DoctorCheck:
    return DoctorCheck("repository", repo_root.exists(), str(repo_root))


def _check_git(repo_root: Path) -> DoctorCheck:
    if shutil.which("git") is None:
        return DoctorCheck("git", False, "git executable not found")
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return DoctorCheck("git", False, "not inside a git working tree")
    return DoctorCheck("git", True, "git repository detected")


def _check_config(repo_root: Path) -> DoctorCheck:
    path = repo_root / CONFIG_FILE
    if not path.exists():
        return DoctorCheck("config", False, f"{CONFIG_FILE} not found")
    config = load_config(repo_root)
    detail = (
        f"{len(config.ignored_paths)} ignored path(s), "
        f"{len(config.custom_sinks)} custom sink(s)"
    )
    return DoctorCheck("config", True, detail)


def _check_graph(repo_root: Path) -> DoctorCheck:
    db_path = repo_root / ".cybergraph" / "graph.db"
    if not db_path.exists():
        return DoctorCheck("graph", False, "graph database not built")
    store = GraphStore.open_for_repo(repo_root)
    try:
        counts = store.counts()
    finally:
        store.close()
    return DoctorCheck(
        "graph",
        counts["nodes"] > 0,
        f"{counts['nodes']} node(s), {counts['edges']} edge(s), {counts['findings']} finding(s)",
    )


def _check_workflow(repo_root: Path) -> DoctorCheck:
    workflow = repo_root / ".github" / "workflows" / "cybergraph.yml"
    if not workflow.exists():
        return DoctorCheck("github action", False, "workflow not installed")
    return DoctorCheck("github action", True, ".github/workflows/cybergraph.yml")
