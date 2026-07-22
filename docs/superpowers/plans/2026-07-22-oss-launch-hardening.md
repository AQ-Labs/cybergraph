# OSS Launch Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add every launch-hardening item that is a file or workflow change (community-health files, supply-chain workflows, SHA-pinned + least-privilege workflows, gated Trusted-Publishing release) plus a maintainer runbook for UI-only settings — with a regex guard test enforcing the hardening.

**Architecture:** Pure config/docs PR — zero product-code changes. A guard test (`tests/test_workflow_hardening.py`) is written FIRST and grows with each task, so every hardening claim is machine-checked. Workflow edits preserve behavior (same action majors, same triggers, same gates); CodeQL/Scorecard are gated off while the repo is private.

**Tech Stack:** GitHub Actions YAML, Dependabot config, Markdown, pytest + `re` (stdlib only — NO PyYAML).

## Global Constraints

- **No product-code changes**: `src/` untouched; full suite (272 tests + new guard tests) green; `ruff check --select F src tests` clean.
- **SHA resolution at implement time**: every pin resolved via `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag> 'refs/tags/<tag>^{}'` — use the `^{}` (dereferenced) SHA when present, else the plain tag SHA. Annotate every pin with a trailing `# <tag>` comment. NEVER use a SHA from memory or training data.
- **Keep existing action majors**: ci.yml/release.yml stay on their v4/v5-era tags; cybergraph.yml stays on its v6/v7-era tags. No major upgrades.
- **Private-repo gates**: `codeql.yml` and `scorecard.yml` jobs carry `if: github.event.repository.private == false`.
- **Release gate preserved**: publish job keeps `if: ${{ vars.ENABLE_PYPI_PUBLISH == 'true' }}`; no API-token path remains.
- **Locked content decisions**: disclosure = GitHub Private Vulnerability Reporting + fallback `lxh417bham@gmail.com`; response ≤ 14 days; medium+ fixes ≤ 60 days; DCO via `Signed-off-by`; CODEOWNERS = `* @Hasan-Laraib`; no numeric coverage gate.
- Tests: `PYTHONPATH=src python -m pytest -q` from repo root.
- Commits authored as the user only — NO `Co-Authored-By: Claude` trailer.

## File Structure

- `tests/test_workflow_hardening.py` (CREATE, Task 1; extended in Tasks 3–5)
- `.github/workflows/ci.yml`, `cybergraph.yml`, `release.yml` (MODIFY, Tasks 2–3)
- `.github/dependabot.yml`, `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml` (CREATE, Task 4)
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/*`, `.github/PULL_REQUEST_TEMPLATE.md` (CREATE, Task 5)
- `docs/OSS_LAUNCH_READINESS.md` (CREATE, Task 6)

---

### Task 1: Guard test (written first, fails on current workflows)

**Files:**
- Test: `tests/test_workflow_hardening.py`

**Interfaces:**
- Produces: module-level `WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"` and tests `test_every_workflow_declares_top_level_permissions`, `test_every_action_is_sha_pinned_with_tag_comment`. Later tasks APPEND tests to this file.

- [ ] **Step 1: Write the failing test**

Create `tests/test_workflow_hardening.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py -q`
Expected: FAIL — ci.yml/release.yml lack top-level `permissions:`; all `uses:` are tag-pinned.

- [ ] **Step 3: Commit the red test** (it documents the target; CI won't run it until push, and the branch is not pushed until the suite is green)

```bash
git add tests/test_workflow_hardening.py
git commit -m "test(ci): add workflow hardening guard (permissions + SHA pins)"
```

---

### Task 2: Harden ci.yml and cybergraph.yml

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/cybergraph.yml`
- Test: `tests/test_workflow_hardening.py` (from Task 1; do not edit)

**Interfaces:**
- Consumes: Task 1's guard tests.
- Produces: hardened ci/cybergraph workflows (release.yml still red → fixed in Task 3).

- [ ] **Step 1: Resolve the SHAs for the tags these workflows already use**

```bash
for spec in "actions/checkout v4" "actions/setup-python v5" \
            "actions/checkout v6" "actions/setup-python v6" \
            "actions/upload-artifact v7" "github/codeql-action v4"; do
  set -- $spec
  echo "== $1 @ $2 =="
  git ls-remote "https://github.com/$1" "refs/tags/$2" "refs/tags/$2^{}"
done
```

Use the `^{}` SHA when printed, else the plain tag SHA. Record each as `<sha> # <tag>`.
(For `github/codeql-action/upload-sarif@v4` the pin applies to the repo tag: `github/codeql-action/upload-sarif@<sha> # v4`.)

- [ ] **Step 2: Edit `ci.yml`**

Insert after the `on:` block (before `jobs:`):

```yaml
permissions:
  contents: read
```

Replace all four action references with pinned forms (using Step 1 SHAs):
- `actions/checkout@v4` → `actions/checkout@<sha-of-v4> # v4` (2 occurrences)
- `actions/setup-python@v5` → `actions/setup-python@<sha-of-v5> # v5` (2 occurrences)

No other changes — triggers, matrix, and steps stay identical.

- [ ] **Step 3: Edit `cybergraph.yml`**

Replace the current top-level permissions block (lines 8–12):

```yaml
permissions:
  contents: read
```

Add the removed elevations at the JOB level — inside `jobs: security-graph:` directly after `runs-on: ubuntu-latest`:

```yaml
    permissions:
      contents: read
      pull-requests: write
      security-events: write
      actions: read
```

Pin the four actions (keeping their existing majors): `actions/checkout@<sha> # v6`, `actions/setup-python@<sha> # v6`, `github/codeql-action/upload-sarif@<sha> # v4`, `actions/upload-artifact@<sha> # v7`. No other changes (the SARIF-upload `if:` and `continue-on-error` stay).

- [ ] **Step 4: Run the guard test — expect release.yml to be the ONLY remaining failure**

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py -q`
Expected: still FAIL, but every reported violation is in `release.yml` (ci.yml and cybergraph.yml clean). If ci/cybergraph still appear, fix them before proceeding.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/cybergraph.yml
git commit -m "ci: least-privilege permissions and SHA-pinned actions"
```

---

### Task 3: release.yml — Trusted Publishing (gated) + hardening

**Files:**
- Modify: `.github/workflows/release.yml`
- Test: `tests/test_workflow_hardening.py` (APPEND release assertions)

**Interfaces:**
- Consumes: Task 1 guard tests; SHA-resolution procedure from Task 2 Step 1.
- Produces: fully green `test_workflow_hardening.py` for all three existing workflows.

- [ ] **Step 1: Append the failing release assertions to `tests/test_workflow_hardening.py`**

```python
def test_release_uses_trusted_publishing_not_api_token():
    text = (WORKFLOW_DIR / "release.yml").read_text(encoding="utf-8")
    assert "id-token: write" in text, "publish job must request OIDC id-token"
    assert "PYPI_API_TOKEN" not in text, "API-token path must be removed"
    assert "TWINE_PASSWORD" not in text, "twine credential env must be removed"
    assert "pypa/gh-action-pypi-publish" in text
    assert "ENABLE_PYPI_PUBLISH" in text, "publish gate must be preserved"
```

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py::test_release_uses_trusted_publishing_not_api_token -q`
Expected: FAIL (`id-token` absent, `PYPI_API_TOKEN` present).

- [ ] **Step 2: Resolve additional SHAs**

```bash
git ls-remote "https://github.com/actions/upload-artifact" refs/tags/v4 "refs/tags/v4^{}"
git ls-remote "https://github.com/actions/download-artifact" refs/tags/v4 "refs/tags/v4^{}"
# newest v1.x release of the PyPI publish action (attestations default-on since v1.11):
git ls-remote --tags "https://github.com/pypa/gh-action-pypi-publish" | grep -E 'refs/tags/v1[0-9.]*\^\{\}' | sort -t/ -k3 -V | tail -3
```

Pick the highest `v1.x.y` tag for `pypa/gh-action-pypi-publish`; record `<sha> # <tag>`.

- [ ] **Step 3: Rewrite `release.yml`**

Full new content (substitute the resolved SHAs):

```yaml
name: release

# Builds and validates distributions on every version tag, then publishes to
# PyPI via Trusted Publishing (OIDC) with PEP 740 attestations (default-on in
# pypa/gh-action-pypi-publish v1.11+). Publishing is opt-in: it only runs when
# the repository variable ENABLE_PYPI_PUBLISH is 'true', which the maintainer
# should set only AFTER registering this repo+workflow as a Trusted Publisher
# on PyPI (see docs/OSS_LAUNCH_READINESS.md, "PyPI Trusted Publisher" runbook
# step). No API token is used anywhere in this workflow.
on:
  push:
    tags:
      - "v*"

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha-of-v4> # v4
      - uses: actions/setup-python@<sha-of-v5> # v5
        with:
          python-version: "3.11"
      - name: Build sdist and wheel
        run: |
          python -m pip install --upgrade build twine
          python -m build
      - name: Validate metadata and wheel contents
        run: |
          python -m twine check dist/*
          python - <<'PY'
          import glob, zipfile
          wheel = sorted(glob.glob("dist/*.whl"))[-1]
          names = zipfile.ZipFile(wheel).namelist()
          assert any("assets/cytoscape.min.js" in n for n in names), "cytoscape asset missing from wheel"
          print("wheel OK:", wheel)
          PY
      - uses: actions/upload-artifact@<sha-of-v4> # v4
        with:
          name: dist
          path: dist/*

  publish:
    needs: build
    runs-on: ubuntu-latest
    # Opt-in gate: requires the PyPI Trusted Publisher registration first.
    if: ${{ vars.ENABLE_PYPI_PUBLISH == 'true' }}
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@<sha-of-v4> # v4
        with:
          name: dist
          path: dist
      - name: Publish to PyPI (Trusted Publishing + PEP 740 attestations)
        uses: pypa/gh-action-pypi-publish@<sha> # <v1.x.y tag>
```

Note the build steps/validation are IDENTICAL to today's; only permissions, pins, and the publish job change.

- [ ] **Step 4: Run the full guard suite — expect ALL green**

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py -q`
Expected: PASS (all workflows pinned + permissioned; release assertions pass).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml tests/test_workflow_hardening.py
git commit -m "ci(release): gated PyPI Trusted Publishing with PEP 740 attestations"
```

---

### Task 4: Dependabot + CodeQL + Scorecard workflows

**Files:**
- Create: `.github/dependabot.yml`
- Create: `.github/workflows/codeql.yml`
- Create: `.github/workflows/scorecard.yml`
- Test: `tests/test_workflow_hardening.py` (APPEND)

**Interfaces:**
- Consumes: guard tests (new workflows are automatically covered by the pin/permissions tests); SHA procedure from Task 2 Step 1.
- Produces: supply-chain automation, gated for the private phase.

- [ ] **Step 1: Append the failing assertions**

```python
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
```

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py::test_supply_chain_configs_exist_and_are_gated -q`
Expected: FAIL (files missing).

- [ ] **Step 2: Create `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
```

- [ ] **Step 3: Resolve SHAs for the new workflows**

```bash
git ls-remote "https://github.com/github/codeql-action" refs/tags/v4 "refs/tags/v4^{}"
git ls-remote --tags "https://github.com/ossf/scorecard-action" | grep -E 'v2[0-9.]*\^\{\}' | sort -t/ -k3 -V | tail -3
git ls-remote "https://github.com/actions/checkout" refs/tags/v4 "refs/tags/v4^{}"
```

Use codeql-action v4 (the major already used by cybergraph.yml) and the newest ossf/scorecard-action v2.x.

- [ ] **Step 4: Create `.github/workflows/codeql.yml`**

```yaml
name: codeql

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "24 5 * * 1"

permissions:
  contents: read

jobs:
  analyze:
    name: CodeQL (python)
    runs-on: ubuntu-latest
    # CodeQL needs a public repo (or GHAS); skip while private so CI stays green.
    if: github.event.repository.private == false
    permissions:
      contents: read
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@<sha-of-v4> # v4
      - uses: github/codeql-action/init@<sha-of-v4> # v4
        with:
          languages: python
      - uses: github/codeql-action/analyze@<sha-of-v4> # v4
```

- [ ] **Step 5: Create `.github/workflows/scorecard.yml`**

```yaml
name: scorecard

on:
  branch_protection_rule:
  push:
    branches: [main]
  schedule:
    - cron: "30 6 * * 1"

permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    # Scorecard publishing targets public repos; skip while private.
    if: github.event.repository.private == false
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@<sha-of-v4> # v4
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@<sha> # <v2.x.y tag>
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@<sha-of-v4> # v4
        with:
          sarif_file: results.sarif
```

- [ ] **Step 6: Run the full guard suite**

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py -q`
Expected: PASS — the pin/permissions tests automatically cover the two new workflows.

- [ ] **Step 7: Commit**

```bash
git add .github/dependabot.yml .github/workflows/codeql.yml .github/workflows/scorecard.yml tests/test_workflow_hardening.py
git commit -m "ci: add Dependabot, CodeQL, and OpenSSF Scorecard (gated while private)"
```

---

### Task 5: Community-health files, templates, CODEOWNERS

**Files:**
- Create: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- Create: `.github/CODEOWNERS`, `.github/PULL_REQUEST_TEMPLATE.md`,
  `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`,
  `.github/ISSUE_TEMPLATE/config.yml`
- Test: `tests/test_workflow_hardening.py` (APPEND existence test)

- [ ] **Step 1: Append the failing assertions**

```python
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
```

Run + expect FAIL, then create the files:

- [ ] **Step 2: `SECURITY.md`**

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest 0.x release | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for security reports.**

1. **Preferred:** use GitHub's private vulnerability reporting — go to the
   repository's **Security** tab → **Report a vulnerability**. Your report is
   visible only to the maintainers.
2. **Fallback:** email `lxh417bham@gmail.com` with a description, reproduction
   steps, and the affected version/commit.

## What to expect

- **Initial response within 14 days** of your report (usually much sooner).
- Confirmed vulnerabilities of medium or higher severity are targeted for a
  fix **within 60 days** of the report or of the issue becoming publicly known.
- We practice coordinated disclosure: we will agree a disclosure timeline with
  you and credit you in the advisory unless you prefer otherwise.

## Scope

- The `cybergraph` CLI and library (`src/cybergraph/`).
- The MCP server (`cybergraph-mcp`) — a **programmatic surface**: reports about
  prompt-injection, tool-abuse, or data exfiltration through the MCP interface
  are explicitly in scope.
- The generated HTML report (XSS/redaction bypasses are in scope; see the
  secret-redaction tests before filing).
```

- [ ] **Step 3: `CONTRIBUTING.md`**

```markdown
# Contributing to CyberGraph

Thanks for your interest! This guide covers everything needed to land a change.

## Dev setup

```bash
python -m pip install -e ".[dev,mcp]"
```

## Tests and lint (both are required CI gates)

```bash
python -m pytest -q                         # full suite must pass
python -m ruff check --select F src tests   # no unused imports / F-errors
```

## Pull-request flow

1. Fork/branch from `main` (never commit to `main` directly).
2. Make focused commits using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(report): ...`, `fix(cli): ...`, `docs: ...`, `test: ...`, `refactor: ...`.
3. **Sign off every commit (DCO).** We use the [Developer Certificate of
   Origin](https://developercertificate.org/). Add `-s` to each commit:
   `git commit -s -m "feat: ..."` which appends `Signed-off-by: Your Name <you@example.com>`.
4. Open a PR; one maintainer review is required. PRs are merged with a merge
   commit or rebase (we do not squash).

## What makes a good PR

- Tests for any behavior change (we practice TDD where practical).
- No new runtime dependencies without prior discussion in an issue.
- User-facing changes get a line in `CHANGELOG.md` under `Unreleased`.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — never open a public issue for vulnerabilities.
```

- [ ] **Step 4: `CODE_OF_CONDUCT.md`** — Contributor Covenant v2.1 verbatim. Fetch the canonical Markdown and fill in the contact:

```bash
curl -fsSL -o CODE_OF_CONDUCT.md https://raw.githubusercontent.com/EthicalSource/contributor_covenant/release/content/version/2/1/code_of_conduct.md
```

Then replace the `[INSERT CONTACT METHOD]` placeholder with `lxh417bham@gmail.com`. If the fetch fails, copy the text from https://www.contributor-covenant.org/version/2/1/code_of_conduct/ manually — do NOT paraphrase it.

- [ ] **Step 5: `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- OSS launch hardening: security policy, contributor docs, Dependabot, CodeQL,
  OpenSSF Scorecard, SHA-pinned least-privilege workflows, and a gated PyPI
  Trusted Publishing release pipeline.

## [0.1.0]

Initial release: security knowledge-graph build (`build`), multi-language
analyzers (Python, JS/TS, Go, Java, C#, Terraform, Dockerfile), one-command
`analyze` and `quickstart`, scan history with deltas (`history`), interactive
theme-aware HTML report with posture grade and attack-path explorer, scanner
imports (Semgrep/SARIF/Gitleaks/OSV/npm audit), reachability-aware SCA, SARIF
and OpenGraph export, evidence-grounded `ask`/`explain`, and an MCP server.
```

- [ ] **Step 6: `.github/CODEOWNERS`, PR template, issue templates**

`.github/CODEOWNERS`:

```
* @Hasan-Laraib
```

`.github/PULL_REQUEST_TEMPLATE.md`:

```markdown
## What does this PR do?

<!-- Short description + motivation. Link related issues: Fixes #123 -->

## Checklist

- [ ] `python -m pytest -q` passes locally
- [ ] `python -m ruff check --select F src tests` is clean
- [ ] Commits follow Conventional Commits and are signed off (`git commit -s`, DCO)
- [ ] Tests added/updated for behavior changes
- [ ] `CHANGELOG.md` updated under `Unreleased` (user-facing changes)
```

`.github/ISSUE_TEMPLATE/bug_report.md`:

```markdown
---
name: Bug report
about: Something broke or produced wrong results
labels: bug
---

**Describe the bug**

**To reproduce**
1. Command(s) run (e.g. `cybergraph analyze <repo>`):
2. Target repo characteristics (language, size):
3. What happened:

**Expected behavior**

**Environment**
- OS:
- Python version:
- CyberGraph version (`cybergraph --version`):

**Additional context** (logs, report screenshots — please redact secrets)
```

`.github/ISSUE_TEMPLATE/feature_request.md`:

```markdown
---
name: Feature request
about: Suggest an idea or improvement
labels: enhancement
---

**Problem / motivation**

**Proposed solution**

**Alternatives considered**

**Additional context**
```

`.github/ISSUE_TEMPLATE/config.yml`:

```yaml
blank_issues_enabled: false
contact_links:
  - name: Report a security vulnerability (private)
    url: https://github.com/khan-ARK/cybergraph/security/advisories/new
    about: Please DO NOT open public issues for security reports.
```

- [ ] **Step 7: Run tests + commit**

Run: `PYTHONPATH=src python -m pytest tests/test_workflow_hardening.py -q` → PASS.

```bash
git add SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md .github/CODEOWNERS .github/PULL_REQUEST_TEMPLATE.md .github/ISSUE_TEMPLATE/ tests/test_workflow_hardening.py
git commit -m "docs: add community-health files, templates, and CODEOWNERS"
```

---

### Task 6: Runbook + report doc, full-suite gate

**Files:**
- Create: `docs/OSS_LAUNCH_READINESS.md`

- [ ] **Step 1: Write `docs/OSS_LAUNCH_READINESS.md`** with these sections (content from the approved research report + spec; write it out fully, no stubs):

1. **Rubric summary** — OpenSSF Scorecard (18 checks / 3 themes, 0–10 scores; cite scorecard.dev + docs/checks.md) and Best Practices Badge passing criteria (≤14-day response, ≤60-day medium+ fixes, https delivery; cite bestpractices.dev). Note the two REFUTED claims (the "23 checks" figure; numeric badge coverage thresholds) so nobody re-introduces them.
2. **Gap table** — every rubric item with status after this PR (✅ file/workflow merged, 🔲 UI step pending, 🔮 post-public), e.g. Branch-Protection 🔲, Token-Permissions ✅, Pinned-Dependencies ✅, Dependency-Update-Tool ✅, SAST ✅ (activates when public), Signed-Releases ✅ (activates on ENABLE_PYPI_PUBLISH), Security-Policy ✅, License ✅ (pre-existing MIT).
3. **Maintainer runbook (UI-only steps, exact click-paths):**
   - Enable Private Vulnerability Reporting: Settings → Code security → "Private vulnerability reporting" → Enable.
   - Branch protection on `main`: Settings → Branches → Add rule: require a pull request before merging (1 approval), require status checks (`test (...)` matrix jobs + `install-from-wheel (...)`), require branches up to date, block force pushes and deletions. Note: also ends direct pushes to main.
   - Secret scanning + push protection + Dependabot alerts: Settings → Code security (note: full secret scanning requires the repo to be public or GHAS; enable at flip-to-public).
   - Install the DCO app: https://github.com/apps/dco → configure for the repo; make its check required in branch protection.
   - **PyPI Trusted Publisher (required before first publish):** on pypi.org → project (or pending publisher) → Publishing → Add GitHub publisher: owner `khan-ARK`, repository `cybergraph`, workflow `release.yml`, environment blank. THEN set repo variable `ENABLE_PYPI_PUBLISH=true` (Settings → Secrets and variables → Actions → Variables). Delete the now-unused `PYPI_API_TOKEN` secret.
   - Flip to public: Settings → General → Danger Zone → Change visibility. CodeQL + Scorecard jobs start running automatically (their private-repo gates lift).
   - OpenSSF Best Practices Badge: register at bestpractices.dev, self-certify passing criteria (this repo satisfies them post-runbook).
   - README badges to add once public: CI, Scorecard, Best Practices (snippet included).
4. **Deferred (explicitly not in this PR):** SLSA L3 generator, OSS-Fuzz, SBOM, GOVERNANCE.md, coverage gates.

- [ ] **Step 2: Full-suite + ruff gate**

Run: `PYTHONPATH=src python -m pytest tests/ -q` → ALL pass (272 + new guard tests).
Run: `ruff check --select F src tests` → clean.

- [ ] **Step 3: Commit**

```bash
git add docs/OSS_LAUNCH_READINESS.md
git commit -m "docs: OSS launch readiness report and maintainer runbook"
```

---

## Self-Review

**1. Spec coverage:** A1–A6 → Task 5; B7–B9 → Task 4; C10–C12 → Tasks 2–3; D13 → Task 6; E14 → Tasks 1/3/4/5 (guard test grows per task). Locked decisions all encoded (disclosure text Task 5 Step 2; DCO Task 5 Step 3; TP gate Task 3; no coverage gate anywhere). ✓
**2. Placeholder scan:** `<sha-of-...>` markers are intentional resolve-at-implement-time instructions mandated by the spec (never hardcode SHAs), each with the exact `git ls-remote` command — not placeholders. CoC uses a canonical-fetch instruction instead of pasted text to guarantee verbatim fidelity. No TBDs. ✓
**3. Type consistency:** `WORKFLOW_DIR` defined Task 1, reused Tasks 3–5 with consistent `parents[0]`/`parents[1]` usage (`.github/` and repo root respectively — verified: `WORKFLOW_DIR.parents[0]` = `.github`, `parents[1]` = repo root). Test names unique. ✓
**4. Checked against real files:** ci.yml has exactly 4 `uses:` (2× checkout@v4, 2× setup-python@v5); cybergraph.yml permissions block is at lines 8–12 and its 4 actions are v6/v6/v4/v7; release.yml build steps preserved verbatim in the Task 3 rewrite; `github.event.repository.private == false` matches cybergraph.yml:58's existing convention. ✓
**5. Risk noted for reviewers:** the guard test runs on ALL `*.yml` in workflows — any future workflow must be born pinned+permissioned (intended ratchet effect).
