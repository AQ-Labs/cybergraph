"""Generate a targeted Strix instruction file from CyberGraph reachability.

Strix (an autonomous AI pentester) is powerful but unfocused: pointed at a repo
it explores broadly, which is slow and expensive. CyberGraph already knows which
routes are reachable, which sinks they hit, and which user input taints them.
This module turns that static reachability knowledge into a Strix
``--instruction-file``: a prioritized "attack these first" brief that shrinks
Strix's search space to the paths most likely to be exploitable.

The output is plain Markdown (Strix reads instruction files as free text). It is
pure static export — no LLM, no network — so it is safe on the offline path.
"""

from __future__ import annotations

from pathlib import Path

from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.remediation import remediation_for_sink
from cybergraph.security.secrets import find_secret_exposures


def build_strix_instructions(repo_root: Path, limit: int = 15) -> str:
    """Return a Markdown instruction brief prioritizing reachable risk for Strix."""
    repo_root = Path(repo_root).resolve()
    paths = find_attack_paths(repo_root, limit=max(limit, 20))
    paths = [p for p in paths if p.risk is not None]
    paths.sort(key=lambda p: (-(p.risk.score if p.risk else 0), not p.data_reachable))
    paths = paths[:limit]
    secrets = find_secret_exposures(repo_root)

    lines: list[str] = [
        "# CyberGraph-guided penetration test scope",
        "",
        "You are testing an application that CyberGraph has already mapped with "
        "static reachability analysis. Prioritize validating the entrypoint-to-sink "
        "paths below, which are reachable from external entrypoints. For each, try "
        "to build a working proof-of-concept and confirm or refute exploitability.",
        "",
        "## Priority attack paths",
        "",
    ]

    if paths:
        for path in paths:
            tainted = "user-controlled input reaches the sink" if path.data_reachable else (
                "structural reachability only (no confirmed tainted argument)"
            )
            risk = f"{path.risk.label}/{path.risk.score}" if path.risk else "n/a"
            lines.append(f"- **{path.entrypoint} -> {path.sink}** (risk {risk})")
            lines.append(f"  - path: {' -> '.join(path.nodes)}")
            lines.append(f"  - why it matters: {tainted}")
            if path.taint_sources:
                lines.append(f"  - user input: {', '.join(path.taint_sources)}")
            lines.append(f"  - expected fix if confirmed: {remediation_for_sink(path.sink)}")
    else:
        lines.append(
            "- No entrypoint-to-sink paths were found statically. Perform a broad "
            "assessment and report any reachable sinks you discover."
        )

    if secrets:
        lines.extend(["", "## Secret exposure paths to validate", ""])
        for exposure in secrets[:limit]:
            reach = "entrypoint-reachable" if exposure.entrypoint_reachable else "internal"
            lines.append(f"- {exposure.function} -> {exposure.sink} ({reach})")

    lines.extend(
        [
            "",
            "## Reporting",
            "",
            "Only report vulnerabilities you validate with a proof-of-concept. For "
            "each confirmed issue include the endpoint, HTTP method, affected file "
            "and lines, severity, and reproduction steps so the result can be "
            "imported back into CyberGraph.",
            "",
        ]
    )
    return "\n".join(lines)


def write_strix_instructions(repo_root: Path, output: Path, limit: int = 15) -> Path:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_strix_instructions(repo_root, limit=limit), encoding="utf-8")
    return output
