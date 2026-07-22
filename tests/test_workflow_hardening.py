"""Guardrails for GitHub Actions hardening (OpenSSF Scorecard alignment).

Regex-based on purpose: PyYAML is not a declared dev dependency.
"""

import re
from pathlib import Path

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _workflows():
    files = sorted(WORKFLOW_DIR.glob("*.yml"))
    assert files, "no workflow files found"
    return files


def test_every_workflow_declares_top_level_permissions():
    for wf in _workflows():
        text = wf.read_text(encoding="utf-8")
        # column-0 'permissions:' = top-level (job-level is indented)
        assert re.search(r"^permissions:", text, re.M), (
            f"{wf.name}: missing top-level permissions block"
        )


def test_every_action_is_sha_pinned_with_tag_comment():
    pin = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\s+#\s*\S+")
    for wf in _workflows():
        for lineno, line in enumerate(
            wf.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if re.search(r"^\s*-?\s*uses:", line):
                assert pin.search(line), (
                    f"{wf.name}:{lineno}: action not SHA-pinned with '# <tag>' "
                    f"comment: {line.strip()}"
                )


def test_release_uses_trusted_publishing_not_api_token():
    text = (WORKFLOW_DIR / "release.yml").read_text(encoding="utf-8")
    assert "id-token: write" in text, "publish job must request OIDC id-token"
    assert "PYPI_API_TOKEN" not in text, "API-token path must be removed"
    assert "TWINE_PASSWORD" not in text, "twine credential env must be removed"
    assert "pypa/gh-action-pypi-publish" in text
    assert "ENABLE_PYPI_PUBLISH" in text, "publish gate must be preserved"


def test_supply_chain_configs_exist_and_are_gated():
    root = WORKFLOW_DIR.parents[0]  # .github/
    assert (root / "dependabot.yml").is_file()
    for name in ("codeql.yml", "scorecard.yml"):
        text = (WORKFLOW_DIR / name).read_text(encoding="utf-8")
        assert "github.event.repository.private == false" in text, (
            f"{name}: must be gated off while the repo is private"
        )
    dep = (root / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: pip" in dep
    assert "package-ecosystem: github-actions" in dep


def test_community_health_files_exist():
    repo = WORKFLOW_DIR.parents[1]
    for rel in (
        "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
        ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
        ".github/ISSUE_TEMPLATE/config.yml",
    ):
        assert (repo / rel).is_file(), f"missing {rel}"
    sec = (repo / "SECURITY.md").read_text(encoding="utf-8")
    assert "lxh417bham@gmail.com" in sec
    assert "14 days" in sec
