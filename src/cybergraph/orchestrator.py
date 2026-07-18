"""Run every analysis once over a single graph build and return one result."""

from __future__ import annotations

import time
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.llm import load_llm_config_from_env
from cybergraph.report_model import AnalysisResult
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.cloud import find_cloud_code_paths
from cybergraph.security.iac_paths import find_iac_attack_paths
from cybergraph.security.investigate import collect_top_risks
from cybergraph.security.layers import summarize_layers
from cybergraph.security.sca import prioritize_vulnerabilities
from cybergraph.security.secrets import find_secret_exposures


def _stage(name, fn, timings, errors, default):
    """Run one analysis stage, isolating failures so the run always completes."""
    start = time.perf_counter()
    try:
        return fn()
    except Exception as exc:  # one bad stage must not abort the whole analysis
        errors[name] = f"{type(exc).__name__}: {exc}"
        return default
    finally:
        timings[name] = time.perf_counter() - start


def run_full_analysis(repo_root: Path, *, limit: int = 10) -> AnalysisResult:
    repo_root = Path(repo_root).resolve()
    timings: dict[str, float] = {}
    errors: dict[str, str] = {}

    counts = _stage("build", lambda: build_graph(repo_root), timings, errors,
                    {"nodes": 0, "edges": 0, "findings": 0})

    top_risks = _stage("top_risks", lambda: collect_top_risks(repo_root, limit=limit),
                        timings, errors, [])
    attack_paths = _stage("attack_paths", lambda: find_attack_paths(repo_root),
                          timings, errors, [])
    secret_exposures = _stage("secret_exposures", lambda: find_secret_exposures(repo_root),
                              timings, errors, [])
    sca = _stage("sca", lambda: prioritize_vulnerabilities(repo_root), timings, errors, [])
    iac_paths = _stage("iac_paths", lambda: find_iac_attack_paths(repo_root),
                       timings, errors, [])
    cloud_code_paths = _stage("cloud_code_paths", lambda: find_cloud_code_paths(repo_root),
                              timings, errors, [])
    layers = _stage("layers", lambda: summarize_layers(repo_root), timings, errors, [])

    return AnalysisResult(
        repo=str(repo_root),
        counts=counts,
        top_risks=top_risks,
        attack_paths=attack_paths,
        secret_exposures=secret_exposures,
        sca=sca,
        iac_paths=iac_paths,
        cloud_code_paths=cloud_code_paths,
        layers=layers,
        truncated=False,
        timings=timings,
        llm_configured=load_llm_config_from_env() is not None,
        errors=errors,
    )
