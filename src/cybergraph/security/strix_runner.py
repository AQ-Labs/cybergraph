"""Optional orchestration bridge that runs Strix and imports its results.

This closes the loop end-to-end: CyberGraph generates a targeted instruction
file (:mod:`cybergraph.security.strix_plan`), invokes the external ``strix`` CLI
scoped to that brief, then imports the validated findings back into the graph
(:mod:`cybergraph.security.strix_imports`).

Strix is heavy (Docker + an LLM API key + network), so it is **never** a
dependency of CyberGraph. This wrapper only runs when the ``strix`` binary and a
running Docker daemon are both detected; otherwise it returns a clear, actionable
message instead of failing. CyberGraph's offline-by-default posture is preserved:
nothing here runs unless the user explicitly invokes ``cybergraph strix-run``.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.strix_imports import load_strix_findings
from cybergraph.security.strix_plan import write_strix_instructions


@dataclass(frozen=True)
class StrixRunResult:
    ran: bool
    message: str
    imported: int = 0
    run_dir: Path | None = None


def strix_available() -> bool:
    return shutil.which("strix") is not None


def docker_running() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        result = subprocess.run(
            [docker, "info"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def run_strix(
    repo_root: Path,
    scan_mode: str = "quick",
    limit: int = 15,
    strix_bin: str | None = None,
    timeout: int = 3600,
) -> StrixRunResult:
    """Generate a scoped brief, run Strix, and import validated findings.

    Returns a :class:`StrixRunResult` describing what happened. Missing tooling
    is reported (not raised) so the CLI can print guidance and exit cleanly.
    """
    repo_root = Path(repo_root).resolve()
    binary = strix_bin or shutil.which("strix")
    if binary is None:
        return StrixRunResult(
            False,
            "Strix is not installed. Install it (pip install strix-agent) and set "
            "LLM_API_KEY/STRIX_LLM, or use 'cybergraph strix-plan' to generate a "
            "scope file and run Strix yourself.",
        )
    if not docker_running():
        return StrixRunResult(
            False,
            "Docker is not running. Strix executes in a Docker sandbox; start "
            "Docker Desktop and retry, or use 'cybergraph strix-plan' instead.",
        )

    instructions = write_strix_instructions(
        repo_root, repo_root / ".cybergraph" / "strix-plan.md", limit=limit
    )
    cmd = [
        binary,
        "-n",
        "-t",
        str(repo_root),
        "-m",
        scan_mode,
        "--instruction-file",
        str(instructions),
    ]
    try:
        # Strix exits non-zero when it finds vulnerabilities; that is success here.
        subprocess.run(cmd, cwd=str(repo_root), timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return StrixRunResult(
            False, f"Strix run exceeded the {timeout}s timeout before completing."
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return StrixRunResult(False, f"Failed to launch Strix: {exc}")

    run_dir = _latest_run_dir(repo_root)
    if run_dir is None:
        return StrixRunResult(
            True,
            "Strix completed but no run output was found under strix_runs/.",
        )
    findings = load_strix_findings(run_dir)
    store = GraphStore.open_for_repo(repo_root)
    try:
        store.add_findings(findings)
    finally:
        store.close()
    return StrixRunResult(
        True,
        f"Strix run complete; imported {len(findings)} validated finding(s) from {run_dir.name}.",
        imported=len(findings),
        run_dir=run_dir,
    )


def _latest_run_dir(repo_root: Path) -> Path | None:
    runs = repo_root / "strix_runs"
    if not runs.is_dir():
        return None
    candidates = [
        p for p in runs.iterdir()
        if p.is_dir()
        and ((p / "vulnerabilities.json").exists() or (p / "findings.json").exists())
    ]
    if not candidates:
        candidates = [p for p in runs.iterdir() if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)
