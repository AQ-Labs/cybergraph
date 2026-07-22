# CyberGraph OSS Launch Readiness

This report documents where CyberGraph stands against the two most widely used open-source
security rubrics — the [OpenSSF Scorecard](https://scorecard.dev/) and the
[OpenSSF Best Practices (CII) Badge](https://www.bestpractices.dev/en) — after the launch-hardening
work merged in this pull request, and lays out the exact UI steps a maintainer with repo-admin
access must still perform (none of which can be done from a code change).

It is organized in four sections:

1. [Rubric summary](#1-rubric-summary) — what the two rubrics actually measure.
2. [Gap table](#2-gap-table) — status of every rubric item after this PR.
3. [Maintainer runbook](#3-maintainer-runbook-ui-only-steps) — exact click-paths for the remaining
   UI-only steps.
4. [Deferred items](#4-deferred-items) — explicitly out of scope for this PR.

---

## 1. Rubric summary

### OpenSSF Scorecard

Scorecard is an automated tool that runs **18 checks across 3 themes** — holistic security
practices, source-code risk, and build-process risk. Each check is scored 0–10 with an associated
risk level, and the results are compiled into a risk-weighted aggregate score.

Sources: <https://scorecard.dev/>, <https://github.com/ossf/scorecard>,
<https://github.com/ossf/scorecard/blob/main/docs/checks.md>

The checks most relevant to CyberGraph, and what they look for (per
[docs/checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md)):

| Check | What earns a high score |
|---|---|
| Branch-Protection | Protected `main`, required reviews, required status checks |
| Code-Review | Human review required before merge |
| Token-Permissions | `permissions` read-only at top level, write declared only at job/step level |
| Pinned-Dependencies | Actions/images/scripts pinned to a full commit SHA (not a tag or branch) |
| Dependency-Update-Tool | Dependabot or Renovate configured |
| SAST | Static analysis (e.g. CodeQL) running in CI |
| CI-Tests | A test suite runs in CI on pull requests |
| Signed-Releases | Release artifacts carry `*.asc`/`*.sig`/`*.sigstore`/`*.intoto.jsonl`; SLSA provenance scores max |
| Security-Policy | A `SECURITY.md` with a vulnerability contact and disclosure terms |
| License | A recognized OSS license file |
| Dangerous-Workflow | No untrusted-input-into-privileged-context patterns |
| Fuzzing | Continuous fuzzing configured (aspirational for a small pre-launch tool) |

### OpenSSF Best Practices (CII) Badge

A free, self-certified web application. Levels are passing / silver / gold, plus a newer baseline
series. The **passing** criteria relevant here require:

- A published vulnerability-reporting process.
- An initial response to reports within **≤ 14 days**.
- No publicly known, unpatched medium-or-higher-severity vulnerability older than **≤ 60 days**.
- MITM-resistant delivery of the project (i.e. **https**).

Cryptographic release signing is a **silver**-level criterion, not a passing-level one.

Sources: <https://www.bestpractices.dev/en>, <https://www.bestpractices.dev/en/criteria>,
<https://openssf.org/projects/best-practices-badge/>

### ⚠️ Refuted claims — do not re-introduce these

> **These two figures were checked against primary sources and found false. If either resurfaces
> in a future PR, planning doc, or slide, it should be corrected, not restated.**
>
> 1. **"Scorecard has 23 checks."** Refuted — the correct, current figure is **18 checks**
>    (see sources above).
> 2. **"Best Practices Badge requires 90% statement / 80% branch coverage at gold."** Refuted —
>    the Badge program asserts no such numeric coverage gate at any level on its own authority.
>    CyberGraph deliberately does **not** set a numeric coverage gate anywhere in this repo.

---

## 2. Gap table

Legend: ✅ merged in this PR &nbsp;·&nbsp; 🔲 UI step pending (maintainer action, see §3) &nbsp;·&nbsp;
🔮 activates automatically post-public, no further action needed.

| Rubric item | Status | Notes |
|---|---|---|
| Token-Permissions | ✅ | Read-only `permissions` at top level in all 5 workflows; write scopes declared only where a job needs them |
| Pinned-Dependencies | ✅ | All `uses:` actions pinned to a full commit SHA (with version comment) across every workflow; enforced going forward by a guard test |
| Dependency-Update-Tool | ✅ | `.github/dependabot.yml` present |
| CI-Tests | ✅ | Pre-existing — `ci.yml` runs the test matrix and lint on every PR/push |
| License | ✅ | Pre-existing MIT `LICENSE` |
| Security-Policy | ✅ | `SECURITY.md` merged (vulnerability contact + disclosure terms, MCP surface declared in scope) |
| Community-health files | ✅ | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue/PR templates, `CODEOWNERS` all present |
| SAST | ✅ / 🔮 | `codeql.yml` merged; gated to run on public repos — starts executing automatically once the repo goes public |
| Scorecard workflow | ✅ / 🔮 | `scorecard.yml` merged; same public-repo gate as SAST |
| Signed-Releases | ✅ / 🔮 | `release.yml` uses Trusted Publishing + PEP 740 attestations via `pypa/gh-action-pypi-publish`; the publish job itself is gated on the `ENABLE_PYPI_PUBLISH` repo variable, set only after PyPI Trusted Publisher registration (§3) |
| Branch-Protection | 🔲 | Requires a repo-admin UI action — cannot be expressed as a file in this repo (§3) |
| Code-Review requirement | 🔲 | Set as part of the branch-protection rule (§3) |
| Private vulnerability reporting | 🔲 | Repo setting toggle (§3) |
| Secret scanning + push protection + Dependabot alerts | 🔲 | Repo setting toggle; full feature set requires public visibility or GHAS (§3) |
| DCO check | 🔲 | Requires installing the DCO GitHub App and marking its check required (§3) |
| PyPI Trusted Publisher registration | 🔲 | Must be registered on pypi.org before first publish; then flip `ENABLE_PYPI_PUBLISH` (§3) |
| Best Practices Badge | 🔲 | Self-certification on bestpractices.dev (§3) |
| Repo visibility (public) | 🔲 / 🔮 | Flipping to public is itself a UI step; it automatically lifts the CodeQL/Scorecard/secret-scanning gates above |
| README badges (CI, Scorecard, Best Practices) | 🔮 | Add once public — badges resolve to real data only then (§3 has the snippet) |

---

## 3. Maintainer runbook (UI-only steps)

These steps require repo-admin access in the GitHub UI (and, for PyPI, project-owner access on
pypi.org). None of them can be merged as code. Do them in the order listed — later steps depend on
earlier ones.

### 3.1 Enable Private Vulnerability Reporting

Settings → Code security → **Private vulnerability reporting** → Enable.

### 3.2 Branch protection on `main`

Settings → Branches → **Add branch protection rule** (pattern: `main`):

- ✅ Require a pull request before merging — **1 required approval** (enables the Code-Review check).
- ✅ Require status checks to pass before merging — add every job produced by the `test (...)`
  matrix in `ci.yml` (one per OS × Python-version combination) plus every `install-from-wheel (...)`
  matrix job. (The DCO check, once installed per §3.4, should also be added here.)
- ✅ Require branches to be up to date before merging.
- ✅ Block force pushes.
- ✅ Do not allow deletions.

Note: this also ends direct pushes to `main` for everyone, including admins if that box is checked.

### 3.3 Secret scanning, push protection, Dependabot alerts

Settings → Code security → enable **Secret scanning**, **Push protection**, and **Dependabot
alerts**.

Caveat: full secret-scanning functionality requires the repository to be public (or GHAS on a
private repo). While the repo is still private, enable what's available now; the rest activates
automatically at the flip-to-public step (§3.6).

### 3.4 Install the DCO app

Install <https://github.com/apps/dco> and configure it for this repository. Then go back to the
branch-protection rule from §3.2 and add the DCO check to the required status checks list.

### 3.5 PyPI Trusted Publisher (required before first publish)

Do this **before** the first tagged release:

1. On pypi.org, go to the project (or use "pending publisher" if the project doesn't exist yet) →
   **Publishing** → **Add a new publisher** (GitHub):
   - Owner: `khan-ARK`
   - Repository name: `cybergraph`
   - Workflow name: `release.yml`
   - Environment name: *(leave blank)*
2. Only after that registration exists, set the repo variable that turns on publishing: Settings →
   Secrets and variables → Actions → **Variables** tab → add `ENABLE_PYPI_PUBLISH` = `true`.
3. Delete the now-unused `PYPI_API_TOKEN` secret (Settings → Secrets and variables → Actions →
   Secrets) — publishing uses Trusted Publishing/OIDC exclusively, no token is used anywhere in
   `release.yml`.

### 3.6 Flip the repository to public

Settings → General → Danger Zone → **Change repository visibility** → Public.

This is the single step that lifts the private-repo gates on the CodeQL and Scorecard workflows —
both start executing automatically on the next push/PR with no further configuration, and secret
scanning gains its full public-repo feature set.

### 3.7 OpenSSF Best Practices Badge self-certification

Register the project at <https://www.bestpractices.dev/en> and complete the self-certification
questionnaire. Per §1, this repo satisfies the passing criteria once the runbook above is complete
(published vulnerability process via `SECURITY.md` + private vulnerability reporting, https
delivery via GitHub/PyPI).

### 3.8 Add README badges (once public)

Add to the top of `README.md`:

```markdown
[![CI](https://github.com/khan-ARK/cybergraph/actions/workflows/ci.yml/badge.svg)](https://github.com/khan-ARK/cybergraph/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/khan-ARK/cybergraph/badge)](https://scorecard.dev/viewer/?uri=github.com/khan-ARK/cybergraph)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<id>/badge)](https://www.bestpractices.dev/projects/<id>)
```

Replace `<id>` with the numeric project id assigned at registration in §3.7. These badges only
resolve to meaningful data once the repo is public and the corresponding workflows/registration
above are live.

---

## 4. Deferred items

Explicitly **not** in scope for this PR or its runbook. Each is a reasonable follow-up but was
judged unnecessary for initial OSS launch:

- **SLSA L3 generator** — build-provenance generation beyond what Trusted Publishing + PEP 740
  attestations already provide.
- **OSS-Fuzz** integration (continuous fuzzing).
- **SBOM** generation/publication.
- **GOVERNANCE.md** — formal project governance document.
- **Numeric coverage gates** — CyberGraph deliberately sets none, at any threshold (see the
  refuted-claim warning in §1).

Additionally, two areas were under-evidenced during research and were resolved by judgment call
rather than by citable authority:

- **DCO vs. CLA**: CyberGraph adopts DCO as the lighter-weight convention common among
  small-maintainer projects; this is a project choice, not a rubric requirement.
- **MCP-interface threat-model disclosure norms**: no established convention was found, so
  `SECURITY.md` pragmatically declares the MCP surface in scope rather than following a citable
  external norm.
