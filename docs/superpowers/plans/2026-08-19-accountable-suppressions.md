# Accountable Suppressions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Let a config suppression carry a required `reason`, optional `expires`, and optional `approver`; an invalid or expired suppression fails open (stops suppressing, finding re-surfaces) and is surfaced. Backward compatible with the existing flat lists.

**Architecture:** Extend `CyberGraphConfig` with parsed `Suppression`/`SuppressionProblem` objects (new `[[suppressions.rule]]`/`[[suppressions.path]]` tables) beside the legacy flat lists. Teach `suppressions.py` to honor active accountable entries and skip invalid/expired ones, with an injectable `today` for determinism. Surface expired/invalid entries via the policy report.

**Tech Stack:** Python 3.10–3.13, stdlib only (`datetime.date`, `tomllib`), pytest, ruff.

## Global Constraints

- Commits authored as `azizur100389` via the repo git config (GitHub noreply email already set); no AI-attribution/`Co-Authored-By` trailer; never squash; push only to `AQ-Labs/cybergraph`.
- **No work/session email in any file** — use neutral placeholders (e.g. `security-team`, `alice@example.com`) in examples/tests.
- Fail-open is mandatory: invalid/expired/malformed suppression must NEVER keep suppressing.
- Backward compatibility: repos using only `[suppressions] rules`/`paths` must behave exactly as before.
- `today` defaults to `date.today()` so existing callers are unchanged; tests always pass an explicit `today`.
- Full suite stays green; ruff clean; test output pristine (0 warnings).

---

### Task 1: Suppression config model & parsing

**Files:** Modify `src/cybergraph/config.py`. Test `tests/test_config_suppressions.py` (new).

**Interfaces — Produces:**
- `@dataclass(frozen=True) class Suppression`: `kind: str` (`"rule"` | `"path"`), `matcher: str` (rule id or path glob), `reason: str`, `expires: date | None`, `approver: str = ""`.
- `@dataclass(frozen=True) class SuppressionProblem`: `kind: str`, `matcher: str`, `message: str`.
- `CyberGraphConfig` gains `suppressions: tuple[Suppression, ...] = ()` and `suppression_problems: tuple[SuppressionProblem, ...] = ()`. Legacy `suppressed_rules`/`suppressed_paths` unchanged.
- Parsing rules (in `load_config`): read `[suppressions].rule` and `[suppressions].path` (each a list of dicts). For each entry: `matcher` from `id` (rule) / `pattern` (path) — missing/empty → `SuppressionProblem`. `reason` required and non-empty → else `SuppressionProblem`. `expires` optional: parse `date.fromisoformat(str)`; a present-but-unparseable value → `SuppressionProblem` (and the entry is dropped, not suppressing). Only fully-valid entries become `Suppression`. `approver` optional string.
- The 3.10 `_load_simple_toml` fallback cannot represent array-of-tables; document that accountable entries require `tomllib` (3.11+), and it must not crash on 3.10 (yields no accountable entries).

- [ ] **Step 1: failing tests**
```python
from datetime import date
from cybergraph.config import load_config, Suppression, SuppressionProblem

def _write(tmp_path, body): (tmp_path/".cybergraph.toml").write_text(body, encoding="utf-8"); return tmp_path

def test_accountable_rule_parsed(tmp_path):
    cfg = load_config(_write(tmp_path, '''
[[suppressions.rule]]
id = "CG-SQL-EXEC"
reason = "fixture only"
expires = "2026-12-31"
approver = "security-team"
'''))
    assert cfg.suppressions == (Suppression("rule","CG-SQL-EXEC","fixture only",date(2026,12,31),"security-team"),)
    assert cfg.suppression_problems == ()

def test_missing_reason_is_a_problem_not_a_suppression(tmp_path):
    cfg = load_config(_write(tmp_path, '[[suppressions.rule]]\nid = "CG-SQL-EXEC"\n'))
    assert cfg.suppressions == ()
    assert any(p.matcher == "CG-SQL-EXEC" and "reason" in p.message.lower() for p in cfg.suppression_problems)

def test_malformed_expires_is_a_problem(tmp_path):
    cfg = load_config(_write(tmp_path, '[[suppressions.rule]]\nid="CG-SQL-EXEC"\nreason="x"\nexpires="not-a-date"\n'))
    assert cfg.suppressions == ()
    assert any("expires" in p.message.lower() for p in cfg.suppression_problems)

def test_legacy_flat_lists_still_parse(tmp_path):
    cfg = load_config(_write(tmp_path, '[suppressions]\nrules = ["CG-SQL-EXEC"]\npaths = ["legacy/**"]\n'))
    assert cfg.suppressed_rules == ("CG-SQL-EXEC",)
    assert cfg.suppressed_paths == ("legacy/**",)
    assert cfg.suppressions == ()  # flat lists are not accountable objects
```
- [ ] **Step 2:** run — expect ImportError/failures.
- [ ] **Step 3:** implement the dataclasses + parsing (a `_parse_suppressions(data) -> (tuple[Suppression,...], tuple[SuppressionProblem,...])` helper; guard the 3.10 fallback path).
- [ ] **Step 4:** run to green; `ruff check`.
- [ ] **Step 5:** commit — `feat(suppressions): accountable suppression config model (reason/expires/approver)`.

---

### Task 2: Validity + expiry logic (fail-open, injectable today)

**Files:** Modify `src/cybergraph/suppressions.py`. Test `tests/test_suppressions_expiry.py` (new).

**Interfaces — Consumes:** `Suppression`, `SuppressionProblem`, `CyberGraphConfig` from Task 1.
**Produces:**
- `active_suppressions(config, today=None) -> list[Suppression]` — accountable entries that are valid and not expired (`expires is None or expires >= today`); `today` defaults to `date.today()`.
- `suppression_problems(config, today=None) -> list[SuppressionProblem]` — `config.suppression_problems` (parse-time) PLUS a `SuppressionProblem(kind, matcher, "expired on <date>")` for each accountable entry with `expires < today`.
- `_rule_suppresses(rule_id, config, today=None)` — legacy list match OR an active accountable `rule` suppression whose `matcher` is in `_rule_aliases(rule_id)`.
- `_path_suppresses(file_path, config, today=None)` — legacy match OR an active accountable `path` suppression whose `matcher` fnmatches `file_path`.
- `is_config_suppressed(finding, config, today=None)`, `config_conceals(rule_id, file_path, config, today=None)`, `filter_suppressed_findings(findings, config, today=None)` — all accept and thread `today`; `config_conceals` returns `None` for an expired/invalid entry (finding is NOT "hidden by config").

- [ ] **Step 1: failing tests** (deterministic `today`)
```python
from datetime import date
from cybergraph.config import CyberGraphConfig, Suppression
from cybergraph.suppressions import _rule_suppresses, active_suppressions, suppression_problems
from cybergraph.graph import Finding

TODAY = date(2026, 6, 1)
def cfg(*s): return CyberGraphConfig(suppressions=tuple(s))

def test_active_accountable_suppresses():
    c = cfg(Suppression("rule","CG-SQL-EXEC","x",date(2026,12,31),""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True

def test_expired_does_not_suppress():
    c = cfg(Suppression("rule","CG-SQL-EXEC","x",date(2026,1,1),""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is False
    assert any("expired" in p.message.lower() for p in suppression_problems(c, today=TODAY))

def test_no_expiry_never_expires():
    c = cfg(Suppression("rule","CG-SQL-EXEC","x",None,""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True

def test_legacy_still_suppresses():
    c = CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True

def test_unverified_alias_still_covered():
    c = cfg(Suppression("rule","CG-SQL-EXEC","x",None,""))
    assert _rule_suppresses("CG-SQL-EXEC-UNVERIFIED", c, today=TODAY) is True
```
- [ ] **Step 2:** run — expect failures.
- [ ] **Step 3:** implement; keep the existing `_rule_aliases` one-way alias behavior; default `today` inside each function (`today = today or date.today()`).
- [ ] **Step 4:** run to green; also run `tests/test_suppressions.py` (if present) + `ruff`.
- [ ] **Step 5:** commit — `feat(suppressions): expired/invalid suppressions fail open (injectable today)`.

---

### Task 3: Surface expired & invalid suppressions

**Files:** Modify `src/cybergraph/security/policy_report.py` (and, if needed, the `policy` path in `cli.py`). Test `tests/test_suppression_surfacing.py` (new).

**Interfaces — Consumes:** `suppression_problems` from Task 2.
Render a section in the policy report listing each expired/invalid suppression with its matcher, the problem message, and (when present) its approver — so a disappearance is never unexplained. Empty when there are none.

- [ ] **Step 1: failing test** — a config with one expired and one missing-reason entry produces a policy report containing both matchers and the words "expired" / "reason", and shows the approver when set. Assert nothing is printed for a clean config.
- [ ] **Step 2–4:** implement the rendering (reuse the report's existing formatting helpers); run the test + `tests/test_policy_report.py`; ruff.
- [ ] **Step 5:** commit — `feat(policy): surface expired and invalid suppressions in the policy report`.

---

### Task 4: Inline `expires=` and reason recording

**Files:** Modify `src/cybergraph/suppressions.py`. Test extends `tests/test_suppressions_expiry.py` or a new `tests/test_inline_expiry.py`.

**Interfaces:** `is_inline_suppressed(lines, line_no, rule_id, today=None)` gains `today`. Inline marker grammar: after `cybergraph: ignore`, tokens may include rule ids, `all`, and a single `expires=YYYY-MM-DD`; remaining words are the (optional) reason. An `expires=` in the past, or malformed, makes the marker not suppress (fail-open). A bare `# cybergraph: ignore RULE` still suppresses.

- [ ] **Step 1: failing tests** — `# cybergraph: ignore CG-SQL-EXEC expires=2026-01-01` does not suppress at `today=2026-06-01`; `expires=2026-12-31` does; bare marker still does; malformed `expires=nope` does not suppress.
- [ ] **Step 2–4:** implement token parsing (strip `expires=` before rule matching so it isn't treated as a rule token); run; ruff.
- [ ] **Step 5:** commit — `feat(suppressions): inline suppressions can expire (expires=)`.

---

### Task 5: Documentation

**Files:** Modify `README.md` (suppressions section) and `docs/features.md` (§7 Findings, suppressions & honesty).

Document the accountable form (reason required, optional `expires`/`approver`), the fail-open-on-expiry behavior, backward compatibility with the flat lists, and inline `expires=`. Use neutral placeholders only. Keep the existing anti-overclaim tone.

- [ ] **Step 1:** update both docs.
- [ ] **Step 2:** commit — `docs(suppressions): document accountable suppressions (reason/expiry/approver)`.

---

## Self-review

- Spec coverage: model (T1), semantics/fail-open/expiry/determinism (T2), surfacing (T3), inline (T4), docs (T5). ✓
- Backward compat asserted in T1 (`test_legacy_flat_lists_still_parse`) and T2 (`test_legacy_still_suppresses`). ✓
- Determinism: every touched predicate takes `today`; tests pass a fixed date. ✓
- Type consistency: `Suppression`/`SuppressionProblem` field names identical across T1→T4. ✓
- No sirio email anywhere; placeholders only. ✓
