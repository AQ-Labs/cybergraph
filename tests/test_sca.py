"""Tests for reachability-based SCA prioritization (never drops a CVE)."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.sca import (
    TIER_DECLARED,
    TIER_ENTRYPOINT,
    prioritize_vulnerabilities,
)
from cybergraph.security.vulnerabilities import import_vulnerability_report

# A high-severity CVSS vector (_osv_severity reads C/I/A -> "high").
_CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _write_osv(path: Path, entries: list[tuple[str, str]]) -> None:
    packages = [
        {
            "package": {"name": pkg, "ecosystem": "PyPI", "version": "1.0.0"},
            "vulnerabilities": [
                {"id": vid, "summary": f"{pkg} flaw", "severity": [{"type": "CVSS_V3", "score": _CVSS_HIGH}]}
            ],
        }
        for pkg, vid in entries
    ]
    path.write_text(json.dumps({"results": [{"packages": packages}]}), encoding="utf-8")


def _build_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("usedpkg==1.0\nunusedpkg==1.0\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "import usedpkg\n"
        "@app.route('/x')\n"
        "def handler(request):\n"
        "    return usedpkg.run(request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_sca_ranks_reachable_above_unused_and_keeps_both(tmp_path: Path):
    repo = _build_repo(tmp_path)
    report = tmp_path / "osv.json"
    _write_osv(report, [("usedpkg", "CVE-USED"), ("unusedpkg", "CVE-UNUSED")])
    import_vulnerability_report(repo, report)

    results = prioritize_vulnerabilities(repo)
    ids = [r.vuln_id for r in results]

    # Guardrail: both CVEs retained, none dropped.
    assert set(ids) == {"CVE-USED", "CVE-UNUSED"}
    # Reachable one ranked first.
    assert ids[0] == "CVE-USED"

    by_id = {r.vuln_id: r for r in results}
    assert by_id["CVE-USED"].reach_tier == TIER_ENTRYPOINT
    assert by_id["CVE-UNUSED"].reach_tier == TIER_DECLARED
    assert by_id["CVE-USED"].score > by_id["CVE-UNUSED"].score
    # Same severity, so reachability alone separates priority.
    assert by_id["CVE-USED"].priority == "critical"
    assert "retained" in by_id["CVE-UNUSED"].rationale.lower()


def test_sca_empty_without_imported_vulns(tmp_path: Path):
    repo = _build_repo(tmp_path)
    assert prioritize_vulnerabilities(repo) == []
