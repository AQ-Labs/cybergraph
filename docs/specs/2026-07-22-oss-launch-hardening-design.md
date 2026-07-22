# OSS Launch Hardening — Design Spec

**Date:** 2026-07-22
**Status:** Awaiting review
**Base:** `main` @ `a8b790d`
**Branch:** `feat/oss-launch-hardening`

## Background

CyberGraph is a private repo about to be open-sourced. A verified launch-readiness research
report (OpenSSF Scorecard 18-check rubric + OpenSSF Best Practices Badge + exemplar 30k-star
security tools + PEP 740/PyPI attestations) produced a gap analysis. This spec implements every
gap that is a **file or workflow change**, and documents every gap that is a **GitHub/PyPI UI
setting** in a runbook the maintainer executes.

## Locked decisions

- **Disclosure:** GitHub Private Vulnerability Reporting (primary) + fallback email
  `lxh417bham@gmail.com`. Response commitments: initial response ≤ 14 days; medium+ severity
  fixed ≤ 60 days of public knowledge (Best Practices Badge passing criteria).
- **Contributor agreement:** DCO (`Signed-off-by` line), enforced via the DCO GitHub App
  (app install = runbook item; CONTRIBUTING documents the requirement).
- **Scope:** all repo-file + workflow items now; UI-only settings documented in the runbook.
- **Release:** rewrite `release.yml` publish job to PyPI **Trusted Publishing (OIDC)** with
  automatic **PEP 740 attestations** via `pypa/gh-action-pypi-publish`; keep the existing
  `vars.ENABLE_PYPI_PUBLISH == 'true'` gate so nothing publishes until the maintainer registers
  the trusted publisher on PyPI (runbook step). Remove the API-token path.
- **No numeric coverage gate** (the badge coverage-threshold claim was refuted in research);
  required CI gates remain `ruff --select F` + `pytest`.

## Constraints (Global)

- **No product-code changes.** `src/` is untouched. The full suite (272 tests) must stay green
  and `ruff check --select F src tests` clean.
- **Behavior-preserving workflow edits:** keep each workflow's current action major versions
  (ci/release use v4/v5-era actions; cybergraph.yml uses v6/v7-era) — pin the SHA **of the tag
  each workflow already references**; do not upgrade majors in this PR.
- **SHA resolution at implement time:** every pinned SHA must be resolved with
  `git ls-remote https://github.com/<owner>/<repo> '<tag>^{}'` (dereferenced tag) at
  implementation time, and annotated with a trailing `# <tag>` comment. Never use a SHA from
  memory. If a tag is not an annotated tag (no `^{}` entry), use the plain tag entry's SHA.
- **Private-repo compatibility:** CodeQL and Scorecard workflows must not produce failing
  checks while the repo is private. Gate their jobs with
  `if: github.event.repository.private == false` (the pattern already used in
  `cybergraph.yml:58`). Scorecard's `publish_results: true` is fine because the job simply
  doesn't run while private.
- **Guard test uses regex, not YAML parsing** (PyYAML is not a declared dev dependency):
  assert every workflow declares `permissions:` and every `uses:` is pinned to a 40-hex SHA.
- **Windows-safe docs:** all new files UTF-8; no CLI output changes.
- Commits authored as the user only — NO `Co-Authored-By: Claude` trailer. Merge with a merge
  commit or rebase (never squash).

## A. Community-health & governance files (create)

1. **`SECURITY.md`** (repo root) — sections: Supported Versions (table: latest 0.x ✅);
   Reporting (GitHub Private Vulnerability Reporting link/instructions as primary, fallback
   email `lxh417bham@gmail.com`; ask reporters NOT to open public issues); Response
   commitments (initial response ≤ 14 days, medium+ severity fixes targeted ≤ 60 days);
   Scope note: the MCP server (`cybergraph-mcp`) is a programmatic surface — reports about
   prompt-injection/tool-abuse via MCP are in scope; Disclosure: coordinated disclosure,
   credit offered.
2. **`CONTRIBUTING.md`** (repo root) — dev setup (`python -m pip install -e ".[dev,mcp]"`),
   run tests (`python -m pytest -q`), lint (`python -m ruff check --select F src tests`),
   PR flow (branch → PR → 1 review → merge commit/rebase, never squash), Conventional Commits
   summary with repo examples, **DCO**: every commit must carry
   `Signed-off-by: Name <email>` (`git commit -s`), link to developercertificate.org.
3. **`CODE_OF_CONDUCT.md`** (repo root) — Contributor Covenant v2.1 verbatim, enforcement
   contact `lxh417bham@gmail.com`.
4. **`CHANGELOG.md`** (repo root) — Keep-a-Changelog format: `## [Unreleased]` section, then
   `## [0.1.0]` (the existing tag) with a short summary of the initial release (graph build,
   analyzers, analyze/quickstart/history CLI, HTML report, MCP server, SARIF/OpenGraph
   export).
5. **Issue/PR templates** — `.github/ISSUE_TEMPLATE/bug_report.md`,
   `.github/ISSUE_TEMPLATE/feature_request.md`,
   `.github/ISSUE_TEMPLATE/config.yml` (`blank_issues_enabled: false`; contact link routing
   security reports to the private-reporting page), `.github/PULL_REQUEST_TEMPLATE.md`
   (checklist: tests pass, ruff clean, DCO sign-off, docs updated if user-facing).
6. **`.github/CODEOWNERS`** — `* @Hasan-Laraib`.

## B. Supply-chain workflows (create)

7. **`.github/dependabot.yml`** — two update blocks: `pip` (directory `/`, weekly) and
   `github-actions` (directory `/`, weekly).
8. **`.github/workflows/codeql.yml`** — CodeQL for Python. Top-level
   `permissions: contents: read`; job-level `security-events: write`, `actions: read`.
   Triggers: push/PR on `main` + weekly cron. Job gated
   `if: github.event.repository.private == false`. Actions SHA-pinned
   (`github/codeql-action/init`, `/analyze`, `actions/checkout`).
9. **`.github/workflows/scorecard.yml`** — OpenSSF Scorecard. Top-level
   `permissions: read-all`; job-level `security-events: write`, `id-token: write`.
   Triggers: push on `main` + weekly cron + `branch_protection_rule`. Job gated
   `if: github.event.repository.private == false`. `publish_results: true`.
   Uploads SARIF via `github/codeql-action/upload-sarif`. All actions SHA-pinned.

## C. Existing-workflow hardening (edit)

10. **`ci.yml`** — add top-level `permissions: contents: read`; SHA-pin `actions/checkout@v4`
    and `actions/setup-python@v5` (all four occurrences).
11. **`cybergraph.yml`** — restructure permissions: top-level becomes `contents: read`; move
    `pull-requests: write`, `security-events: write`, `actions: read` to the job level
    (job `security-graph`). SHA-pin `actions/checkout@v6`, `actions/setup-python@v6`,
    `github/codeql-action/upload-sarif@v4`, `actions/upload-artifact@v7`. No behavior change.
12. **`release.yml`** — top-level `permissions: contents: read`. Build job: SHA-pin
    checkout/setup-python/upload-artifact. Publish job: keep
    `if: ${{ vars.ENABLE_PYPI_PUBLISH == 'true' }}`; add job-level
    `permissions: id-token: write`; replace the twine/API-token steps with SHA-pinned
    `actions/download-artifact` + `pypa/gh-action-pypi-publish` (attestations are default-on
    in v1.11+; rely on the default — no explicit `attestations:` input). Delete
    `TWINE_USERNAME`/`TWINE_PASSWORD`/`PYPI_API_TOKEN` usage and update the header comment to
    describe Trusted Publishing + the gate. Add a comment noting publishing requires the
    PyPI trusted-publisher registration (runbook).

## D. Runbook + report (create)

13. **`docs/OSS_LAUNCH_READINESS.md`** — two parts:
    (a) the research report (rubric summary, verified findings with source links, refuted
    claims called out, gap table with ✅/❌ current state);
    (b) **maintainer runbook** of UI-only steps, each with exact click-path: enable Private
    Vulnerability Reporting; branch protection on `main` (require PR, required checks =
    `test` matrix + `install-from-wheel`, require 1 review, block force pushes/deletions);
    enable secret scanning + push protection and Dependabot alerts (note: on the private repo
    some features need GHAS — fully available once public); install the DCO app; register the
    PyPI **trusted publisher** (owner `khan-ARK`, repo `cybergraph`, workflow `release.yml`)
    then set `ENABLE_PYPI_PUBLISH=true`; OpenSSF Best Practices Badge self-certification
    steps; README badges (CI, Scorecard, Best Practices) to add once public.

## E. Guard test (create)

14. **`tests/test_workflow_hardening.py`** — regex-based, no new dependencies:
    - every file in `.github/workflows/*.yml` contains a top-level `permissions:` line;
    - every `uses:` line in those files matches `@[0-9a-f]{40}` (SHA-pinned), with the
      trailing `# <tag>` comment present;
    - `release.yml` contains `id-token: write` and does NOT contain `PYPI_API_TOKEN` or
      `TWINE_PASSWORD`;
    - `codeql.yml` and `scorecard.yml` contain the private-repo gate string
      `github.event.repository.private == false`.

## Error handling & degradation

- While private: CodeQL/Scorecard jobs are skipped (gate), not failed; secret-scanning
  features documented as post-public. Release publish stays inert until the gate var + PyPI
  registration exist. Nothing in this PR can break CI for the current private repo.

## Out of scope

SLSA L3 generator, OSS-Fuzz, SBOM generation, GOVERNANCE.md, numeric coverage gates, action
major-version upgrades, README badge insertion (runbook, post-public).
