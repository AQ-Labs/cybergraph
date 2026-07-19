"""Project initialization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

CONFIG_TEMPLATE = """# CyberGraph project configuration

[ignore]
paths = [
  "node_modules/**",
  "dist/**",
  "build/**",
  "vendor/**",
]

[security]
# Add project-specific sinks, decorators, middleware, or helper names here.
sinks = []
auth_markers = []
validation_markers = []
secret_markers = []

[severity]
overrides = {}
"""


WORKFLOW_TEMPLATE = """name: CyberGraph

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write
  actions: read

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"

jobs:
  security-graph:
    name: Build security graph
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - name: Install CyberGraph
        run: python -m pip install cybergraph

      - name: Build graph
        run: cybergraph build .

      - name: Review security delta
        if: github.event_name == 'pull_request'
        run: cybergraph review --base origin/${{ github.base_ref }} --repo . | tee cybergraph-review.txt

      - name: Generate PR comment
        if: github.event_name == 'pull_request'
        run: cybergraph pr-comment --base origin/${{ github.base_ref }} --repo . --output cybergraph-pr-comment.md

      - name: Comment on pull request
        if: github.event_name == 'pull_request'
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh pr comment ${{ github.event.pull_request.number }} --body-file cybergraph-pr-comment.md

      - name: Export SARIF
        run: cybergraph sarif --repo . --output cybergraph.sarif

      - name: Generate HTML report
        run: cybergraph visualize . --output cybergraph-report.html

      - name: Upload SARIF to code scanning
        if: github.event.repository.private == false || vars.CYBERGRAPH_UPLOAD_SARIF == 'true'
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: cybergraph.sarif

      - name: Upload CyberGraph artifacts
        uses: actions/upload-artifact@v7
        with:
          name: cybergraph-report
          path: |
            cybergraph.sarif
            cybergraph-report.html
            cybergraph-review.txt
            cybergraph-pr-comment.md
          if-no-files-found: ignore
"""


@dataclass(frozen=True)
class InitResult:
    created: tuple[str, ...]
    skipped: tuple[str, ...]


def init_project(repo_root: Path, force: bool = False) -> InitResult:
    repo_root = repo_root.resolve()
    targets = {
        ".cybergraph.toml": CONFIG_TEMPLATE,
        ".github/workflows/cybergraph.yml": WORKFLOW_TEMPLATE,
    }
    created: list[str] = []
    skipped: list[str] = []
    for relative, content in targets.items():
        path = repo_root / relative
        if path.exists() and not force:
            skipped.append(relative)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(relative)
    return InitResult(tuple(created), tuple(skipped))


def format_init_result(result: InitResult) -> str:
    lines = ["CyberGraph init complete."]
    if result.created:
        lines.append("Created:")
        lines.extend(f"- {item}" for item in result.created)
    if result.skipped:
        lines.append("Skipped existing files:")
        lines.extend(f"- {item}" for item in result.skipped)
    lines.extend(
        [
            "",
            "Next commands:",
            "  cybergraph build .",
            "  cybergraph ask \"Which routes reach sensitive sinks?\" --repo .",
            "  cybergraph visualize .",
        ]
    )
    return "\n".join(lines)
