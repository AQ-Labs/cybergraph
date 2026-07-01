"""Tests for transparent risk scoring."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.attack_paths import find_attack_paths, format_attack_paths
from cybergraph.security.iac_paths import find_iac_attack_paths, format_iac_attack_paths
from cybergraph.security.risk import score_dependency_vulnerability, score_risk
from cybergraph.security.sca import format_sca, prioritize_vulnerabilities
from cybergraph.security.vulnerabilities import import_vulnerability_report


def test_risk_score_exposes_factors_and_label() -> None:
    risk = score_risk(
        reachability=1.0,
        exposure=1.0,
        exploitability=0.9,
        impact=0.8,
        confidence="high",
    )

    assert risk.score >= 80
    assert risk.label in {"high", "critical"}
    assert risk.factors["reachability"] == 1.0
    assert "reachability=" in risk.rationale


def test_dependency_risk_uses_reachability_and_advisory_intel() -> None:
    reachable = score_dependency_vulnerability(
        severity="high",
        reach_tier="entrypoint-reachable",
        epss_score=0.91,
        kev=True,
    )
    declared = score_dependency_vulnerability(severity="high", reach_tier="declared-only")

    assert reachable.score > declared.score
    assert reachable.label == "critical"


def test_attack_path_format_includes_risk(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/search')\n"
        "def search(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    paths = find_attack_paths(repo)

    assert paths[0].risk is not None
    assert "risk=" in format_attack_paths(paths)


def test_sca_format_includes_risk(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("usedpkg==1.0\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "import usedpkg\n@app.get('/x')\ndef handler(request):\n    return usedpkg.run()\n",
        encoding="utf-8",
    )
    report = tmp_path / "osv.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": "usedpkg", "ecosystem": "PyPI", "version": "1.0"},
                                "vulnerabilities": [
                                    {
                                        "id": "CVE-USED",
                                        "summary": "demo",
                                        "severity": [{"score": "CVSS:3.1/C:H/I:H/A:H"}],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    build_graph(repo)
    import_vulnerability_report(repo, report)

    output = format_sca(prioritize_vulnerabilities(repo))

    assert "Risk:" in output
    assert "/100" in output


def test_iac_path_format_includes_risk(tmp_path: Path) -> None:
    repo = tmp_path / "iac"
    repo.mkdir()
    (repo / "main.tf").write_text(
        'resource "aws_security_group" "public" {\n'
        '  ingress { cidr_blocks = ["0.0.0.0/0"] }\n'
        "}\n"
        'resource "aws_iam_policy" "admin" {\n'
        "  policy = jsonencode({ Statement = [{ Action = \"*\", Resource = \"*\" }] })\n"
        "}\n"
        'resource "aws_instance" "web" {\n'
        "  vpc_security_group_ids = [aws_security_group.public.id]\n"
        "  iam_instance_profile = aws_iam_policy.admin.name\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)

    paths = find_iac_attack_paths(repo)

    assert paths and paths[0].risk is not None
    assert "risk=" in format_iac_attack_paths(paths)
