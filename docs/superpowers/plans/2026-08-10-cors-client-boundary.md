# CORS + Next.js Client-Secret Boundary — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag two in-code web exposures — a CORS policy that allows any origin *with credentials*, and a secret shipped to the browser via `NEXT_PUBLIC_` — and make a change that introduces either return REVIEW from `cybergraph check`, precisely, with no false alarm on a scoped CORS config or a public-by-design value.

**Architecture:** Extend the two existing code analyzers (`python.py` AST-based, `javascript.py` line/source-based) with new detectors, then activate the declared-but-absent `client_secret_boundary` capability and add a new `cross_origin_policy` capability so their findings drive the verdict. One coverage wiring change lets a changed web file reach PASS/FAIL for these capabilities instead of perpetual UNKNOWN.

**Tech Stack:** Python 3.10–3.13, standard library only (`ast`, `re`, `pathlib`). Existing `graph.Finding/Node`, `suppressions.is_inline_suppressed`, the capability/coverage/checks machinery.

## Global Constraints

- **Zero runtime dependencies**; standard library only. Python 3.10–3.13. `from __future__ import annotations` first line of any new file (both target files already have it).
- Ruff line-length 100; run `ruff check` on every touched file — clean.
- No network; no API keys on any default path.
- **Precision over recall (cardinal):** flag only the definite signals below. An unresolved/dynamic CORS config or an ambiguous name yields NO finding — document the recall gap, never risk a false alarm.
- Findings carry `rule_id`, `severity`, `message`, `file_path`, `line_start`, `cwe`, `evidence`, and honor `is_inline_suppressed` — mirror the existing `Finding(...)` calls in each analyzer.
- Commits authored `Laraib <lxh417bham@gmail.com>` only (repo-local git config already carries it — do **not** pass `-c user.email=`); no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.
- Branch `feat/cors-client-boundary` is stacked on `feat/config-posture`; do not rebase during implementation.

---

## File Structure

- `src/cybergraph/analysis/python.py` (modify) — FastAPI CORS detector (`_add_cors_findings`).
- `src/cybergraph/analysis/javascript.py` (modify) — Express CORS + `NEXT_PUBLIC_` secret detectors.
- `src/cybergraph/security/capability.py` (modify) — activate `client_secret_boundary`; add `cross_origin_policy` + `CORS_GLOBS`.
- `src/cybergraph/security/coverage.py` (modify) — add `WEB_GLOBS` to the verified gate.
- `src/cybergraph/security/checks.py` (modify) — `_FINDING_RULES` += both rule ids.
- Tests: `tests/test_python_cors.py`, `tests/test_js_cors_nextjs.py`, `tests/test_web_capabilities.py` (create); edits to any test asserting these capabilities `NOT_SUPPORTED`.
- `benchmark/mutation_harness.py` (modify) — two seeded fail-opens.
- `README.md` (modify) — one line.

---

## Task 1: FastAPI CORS detector (Python)

**Files:**
- Modify: `src/cybergraph/analysis/python.py`
- Test: `tests/test_python_cors.py` (create)

**Interfaces:**
- Consumes: existing `ast`, `_callable_name`, `Finding`, `is_inline_suppressed`.
- Produces: `_add_cors_findings(tree, rel, lines, findings)` appending `CG-CORS-CREDENTIALED-WILDCARD` (severity `high`, CWE-942); invoked from `analyze_python_file` right after `_add_django_url_routes(tree, rel, nodes, edges)` (python.py:167).

- [ ] **Step 1: Write the failing test**

Create `tests/test_python_cors.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.python import analyze_python_file


def _run(tmp_path: Path, src: str):
    p = tmp_path / "main.py"
    p.write_text(src, encoding="utf-8")
    _nodes, _edges, findings = analyze_python_file(p, tmp_path)
    return [f.rule_id for f in findings]


CRED_WILDCARD = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
"""

SCOPED = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
"""

WILDCARD_NO_CREDS = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])
"""

REGEX_ALL = """from starlette.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)
"""


def test_credentialed_wildcard_is_flagged(tmp_path):
    assert _run(tmp_path, CRED_WILDCARD) == ["CG-CORS-CREDENTIALED-WILDCARD"]


def test_scoped_origin_is_clean(tmp_path):
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, SCOPED)


def test_wildcard_without_credentials_is_clean(tmp_path):
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, WILDCARD_NO_CREDS)


def test_regex_all_origins_with_credentials_is_flagged(tmp_path):
    assert _run(tmp_path, REGEX_ALL) == ["CG-CORS-CREDENTIALED-WILDCARD"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_python_cors.py -v` — Expected: FAIL (no finding emitted yet).

- [ ] **Step 3: Implement `_add_cors_findings`**

In `python.py`, add these helpers (near `_add_django_url_routes`):

```python
def _cors_allows_all(origins: ast.AST | None, regex: ast.AST | None) -> bool:
    if isinstance(origins, (ast.List, ast.Tuple)):
        if any(isinstance(e, ast.Constant) and e.value == "*" for e in origins.elts):
            return True
    if isinstance(origins, ast.Constant) and origins.value == "*":
        return True
    if isinstance(regex, ast.Constant) and isinstance(regex.value, str):
        if regex.value in {".*", "^.*$", "*", ".*$", "^.*", "(.*)"}:
            return True
    return False


def _kw_is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _add_cors_findings(
    tree: ast.AST, rel: str, lines: list[str], findings: list[Finding]
) -> None:
    """Flag a FastAPI/Starlette CORS middleware allowing any origin WITH credentials.

    The credentialed wildcard is the real vulnerability: any site can make
    authenticated cross-origin requests. A scoped origin list, or a wildcard
    without credentials, is not flagged (precision over recall).
    """
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        name = _callable_name(call.func)
        is_cors = name == "CORSMiddleware" or (
            name.endswith("add_middleware")
            and call.args
            and _callable_name(call.args[0]) == "CORSMiddleware"
        )
        if not is_cors:
            continue
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        if not _cors_allows_all(kw.get("allow_origins"), kw.get("allow_origin_regex")):
            continue
        if not _kw_is_true(kw.get("allow_credentials")):
            continue
        line_no = getattr(call, "lineno", 1)
        if is_inline_suppressed(lines, line_no, "CG-CORS-CREDENTIALED-WILDCARD"):
            continue
        findings.append(
            Finding(
                rule_id="CG-CORS-CREDENTIALED-WILDCARD",
                severity="high",
                message="CORS allows any origin with credentials "
                        "(allow_origins '*' + allow_credentials=True)",
                file_path=rel,
                line_start=line_no,
                cwe="CWE-942",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )
```

Invoke it in `analyze_python_file`, immediately after `_add_django_url_routes(tree, rel, nodes, edges)`:

```python
    _add_cors_findings(tree, rel, lines, findings)
```

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_python_cors.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/analysis/python.py tests/test_python_cors.py` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/python.py tests/test_python_cors.py
git commit -m "feat(analysis): detect FastAPI credentialed-wildcard CORS"
```

---

## Task 2: Express CORS + Next.js secret detector (JavaScript)

**Files:**
- Modify: `src/cybergraph/analysis/javascript.py`
- Test: `tests/test_js_cors_nextjs.py` (create)

**Interfaces:**
- Consumes: existing `Finding`, `is_inline_suppressed`, module regex conventions.
- Produces: `_add_js_web_findings(source, lines, rel, findings)` appending `CG-CORS-CREDENTIALED-WILDCARD` (CWE-942) and `CG-CLIENT-SECRET-EXPOSED` (CWE-200); invoked once from `analyze_javascript_file` before `return nodes, edges, findings`.

**Detection rules (operate on the RAW `source`/`lines`, not the strings-blanked `code_lines` — the values we need live inside string literals):**
- **CORS:** a `cors(` call whose options object contains BOTH an all-origins setting (`origin: "*"`, `origin: '*'`, or `origin: true`) AND `credentials: true`. A scoped origin, a bare `cors()` (credentials default off), or credentials-only is clean.
- **Next.js secret:** a `NEXT_PUBLIC_<NAME>` token whose `<NAME>` contains a secret keyword (`SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `PASSWD`, `APIKEY`, `PRIVATE`), case-insensitive. `NEXT_PUBLIC_API_URL` etc. are clean.

- [ ] **Step 1: Write the failing test**

Create `tests/test_js_cors_nextjs.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def _run(tmp_path: Path, name: str, src: str):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_javascript_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_express_credentialed_wildcard_cors_is_flagged(tmp_path):
    src = "const cors = require('cors');\napp.use(cors({ origin: '*', credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" in _run(tmp_path, "server.js", src)


def test_express_origin_true_with_credentials_is_flagged(tmp_path):
    src = "app.use(cors({ origin: true, credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" in _run(tmp_path, "server.js", src)


def test_scoped_cors_is_clean(tmp_path):
    src = "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, "server.js", src)


def test_bare_cors_is_clean(tmp_path):
    src = "app.use(cors());\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, "server.js", src)


def test_next_public_secret_is_flagged(tmp_path):
    src = "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" in _run(tmp_path, "config.ts", src)


def test_next_public_url_is_clean(tmp_path):
    src = "const u = process.env.NEXT_PUBLIC_API_URL;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "config.ts", src)


def test_server_side_secret_is_not_a_client_boundary_finding(tmp_path):
    src = "const k = process.env.STRIPE_SECRET_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "server.ts", src)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_js_cors_nextjs.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the detectors**

In `javascript.py`, add module-level regexes and helpers:

```python
_CORS_CALL_RE = re.compile(r"\bcors\s*\(\s*\{")
_ORIGIN_ALL_RE = re.compile(r"""origin\s*:\s*(?:['"]\*['"]|true)""")
_CREDENTIALS_TRUE_RE = re.compile(r"credentials\s*:\s*true")
_NEXT_PUBLIC_RE = re.compile(
    r"NEXT_PUBLIC_[A-Za-z0-9_]*"
    r"(?:SECRET|APIKEY|API_KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|_KEY|KEY)"
    r"[A-Za-z0-9_]*",
    re.IGNORECASE,
)


def _brace_object(source: str, open_index: int) -> tuple[str, int]:
    """From the '{' at open_index, return (object_text, end_index) at its match."""
    depth = 0
    for i in range(open_index, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_index : i + 1], i
    return source[open_index:], len(source)


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _add_js_web_findings(
    source: str, lines: list[str], rel: str, findings: list[Finding]
) -> None:
    # CORS: cors({ ... origin:*/true ... credentials:true ... })
    for m in _CORS_CALL_RE.finditer(source):
        obj, _end = _brace_object(source, m.end() - 1)
        if _ORIGIN_ALL_RE.search(obj) and _CREDENTIALS_TRUE_RE.search(obj):
            line_no = _line_of(source, m.start())
            if is_inline_suppressed(lines, line_no, "CG-CORS-CREDENTIALED-WILDCARD"):
                continue
            findings.append(
                Finding(
                    rule_id="CG-CORS-CREDENTIALED-WILDCARD",
                    severity="high",
                    message="CORS allows any origin with credentials "
                            "(origin '*'/true + credentials: true)",
                    file_path=rel,
                    line_start=line_no,
                    cwe="CWE-942",
                    evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
                )
            )
    # Next.js: a NEXT_PUBLIC_ name that looks like a secret -> inlined into the bundle.
    seen: set[int] = set()
    for m in _NEXT_PUBLIC_RE.finditer(source):
        line_no = _line_of(source, m.start())
        if line_no in seen:
            continue
        seen.add(line_no)
        if is_inline_suppressed(lines, line_no, "CG-CLIENT-SECRET-EXPOSED"):
            continue
        findings.append(
            Finding(
                rule_id="CG-CLIENT-SECRET-EXPOSED",
                severity="high",
                message=f"`{m.group(0)}` ships a secret to the browser bundle "
                        "(NEXT_PUBLIC_ is inlined client-side)",
                file_path=rel,
                line_start=line_no,
                cwe="CWE-200",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )
```

Invoke once in `analyze_javascript_file`, just before `return nodes, edges, findings`:

```python
    _add_js_web_findings(source, lines, rel, findings)
```

> The `_NEXT_PUBLIC_RE` intentionally requires a secret-ish token after the `NEXT_PUBLIC_` prefix; verify against the test cases that `NEXT_PUBLIC_API_URL` does NOT match (it must not) while `NEXT_PUBLIC_STRIPE_SECRET_KEY` does. Adjust the alternation if a test case reveals an over/under-match — keep `NEXT_PUBLIC_API_URL` clean.

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_js_cors_nextjs.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/analysis/javascript.py tests/test_js_cors_nextjs.py` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/javascript.py tests/test_js_cors_nextjs.py
git commit -m "feat(analysis): detect Express credentialed-wildcard CORS and NEXT_PUBLIC secrets"
```

---

## Task 3: Activate the two web capabilities

**Files:**
- Modify: `src/cybergraph/security/capability.py`
- Modify: `src/cybergraph/security/coverage.py`
- Modify: `src/cybergraph/security/checks.py`
- Modify: any test asserting `client_secret_boundary`/`cross_origin_policy` unsupported
- Test: `tests/test_web_capabilities.py` (create)

**Interfaces:**
- Consumes: rule ids from Tasks 1–2.
- Produces: `client_secret_boundary` `supported=True`; new `cross_origin_policy` capability with `covers=CORS_GLOBS` (`PYTHON_GLOBS + WEB_GLOBS`); `_FINDING_RULES` entries for both; a coverage gate that treats web files as verified so these capabilities can PASS/FAIL.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_capabilities.py`:

```python
from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.security.capability import CAPABILITIES, FAIL
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_both_web_capabilities_supported():
    assert _cap("client_secret_boundary").supported is True
    assert _cap("cross_origin_policy").supported is True


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_python_credentialed_cors_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "cross_origin_policy" and c.status == FAIL
               for c in verdict.checks)


def test_next_public_secret_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "config.ts").write_text(
        "export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n", encoding="utf-8"
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "client_secret_boundary" and c.status == FAIL
               for c in verdict.checks)
```

> Note: confirm `check_change`/`Verdict.checks`/`CheckResult` names against source before finalizing. A `.py`/`.ts` change will also make `source_analysis_support` review (JS) or run other Python capabilities — assert only on the specific capability id + FAIL and the overall REVIEW state, as written.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_web_capabilities.py -v` — Expected: FAIL (capabilities not supported / no FAIL).

- [ ] **Step 3: Activate the capabilities**

In `capability.py`: add `CORS_GLOBS = PYTHON_GLOBS + WEB_GLOBS` near the other `*_GLOBS`. Change the `client_secret_boundary` entry's last field from `False` to `True`. Add a new entry to `CAPABILITIES`:

```python
    Capability("cross_origin_policy", "Cross-origin resource sharing", CORS_GLOBS, True),
```

- [ ] **Step 4: Track web files as verified in coverage**

In `coverage.py`, import `WEB_GLOBS` and add it to the verified gate so an analyzed web file is `ANALYZED` (able to PASS) rather than `UNSUPPORTED`:

```python
from cybergraph.security.capability import CONFIG_GLOBS, SOURCE_GLOBS, VERIFIED_GLOBS, WEB_GLOBS
```

and change the UNSUPPORTED gate to:

```python
        elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS + CONFIG_GLOBS + WEB_GLOBS):
```

> This does NOT change `source_analysis_support`: that capability decides NOT_SUPPORTED via `unverified_source_files` (VERIFIED_GLOBS), which is unchanged, and it pre-filters web files out before consulting coverage. A changed `.js` therefore still makes `source_analysis_support` NOT_SUPPORTED (JS is inventory-grade) while `cross_origin_policy`/`client_secret_boundary` can now PASS/FAIL on it. Verify a Go file (no web glob) stays UNSUPPORTED.

- [ ] **Step 5: Map the rule ids**

In `checks.py`, add to `_FINDING_RULES`:

```python
    "client_secret_boundary": "CG-CLIENT-SECRET-EXPOSED",
    "cross_origin_policy": "CG-CORS-CREDENTIALED-WILDCARD",
```

(Single-rule strings; the existing `{rule} if isinstance(rule, str) else set(rule)` normalization handles them.)

- [ ] **Step 6: Update stale unsupported expectations**

Run `grep -rn "client_secret_boundary\|cross_origin_policy\|NOT_SUPPORTED" tests/` and update any assertion that expected `client_secret_boundary` to be unsupported to the new supported behavior. Change only the expectation, never production code, and never weaken an unrelated assertion. (A `decide()` unit test that constructs a `CheckResult("client_secret_boundary", NOT_SUPPORTED)` by hand is still valid — it tests `decide`, not the capability's flag — leave it unless it asserts the flag.)

- [ ] **Step 7: Run tests + ruff**

Run: `pytest tests/test_web_capabilities.py tests/test_capability.py tests/test_checks.py tests/test_coverage_report.py tests/test_verdict.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/security/capability.py src/cybergraph/security/coverage.py src/cybergraph/security/checks.py tests/test_web_capabilities.py` — Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/cybergraph/security/capability.py src/cybergraph/security/coverage.py src/cybergraph/security/checks.py tests/
git commit -m "feat(verdict): activate cross-origin and client-secret-boundary capabilities"
```

---

## Task 4: Mutation harness + docs + full verification

**Files:**
- Modify: `benchmark/mutation_harness.py` (two seeded fail-opens)
- Modify: `README.md` (one line)
- Verification: full suite, ruff, harness, precision/eval.

**Interfaces:** consumes the finished detectors (Tasks 1–2) and wiring (Task 3).

- [ ] **Step 1: Add the mutations**

Append two `Mutation` entries to `MUTATIONS` in `benchmark/mutation_harness.py`. Match every `old` string to committed source verbatim (open the files; fix the `old` string if it differs — never edit source to fit the mutation).

Mutation A — Python CORS fail-open: the detector is short-circuited so a real credentialed wildcard is never flagged. Target the credentials guard in `python.py`'s `_add_cors_findings` and turn it into an unconditional `continue` (skip every CORS call):
- `old` = `        if not _kw_is_true(kw.get("allow_credentials")):\n            continue`
- `new` = `        if True:\n            continue`
- `tests` = `("tests/test_python_cors.py::test_credentialed_wildcard_is_flagged",)`
- id `D9-cors-credentialed-wildcard-missed`, disaster `D9`, note "a credentialed-wildcard CORS must be flagged, never dropped".

  (Suppressing emission — not `if False` — is what makes `test_credentialed_wildcard_is_flagged` go red; `if False` would still flag the credentialed case and merely add false positives, which a fail-open test does not catch.)

Mutation B — Next.js secret fail-open (the client-boundary finding is never emitted). Target the append or the regex in `javascript.py`. Simplest robust target: the `_NEXT_PUBLIC_RE` alternation, replacing the secret keywords with a token that cannot match a real name:
- `old` = the exact `_NEXT_PUBLIC_RE = re.compile(` line block — copy the committed multi-line assignment verbatim; if multi-line editing is awkward, instead target the single guard line where the finding is appended (e.g. wrap the `NEXT_PUBLIC_` loop body so nothing is appended). The invariant under test: `test_next_public_secret_is_flagged` must FAIL under the mutation.
- `new` = a form that makes the loop emit nothing (e.g. `_NEXT_PUBLIC_RE = re.compile(r"__CYBERGRAPH_NEVER_MATCHES__")`).
- `tests` = `("tests/test_js_cors_nextjs.py::test_next_public_secret_is_flagged",)`
- id `D9-client-secret-exposure-missed`, disaster `D9`, note "a NEXT_PUBLIC_ secret must be flagged, never missed".

- [ ] **Step 2: Run the harness**

Run: `python benchmark/mutation_harness.py` — Expected: every mutation CAUGHT, incl. the two new ones. (Use `--only`/`--id` if supported to iterate.)

- [ ] **Step 3: Document in the README**

Add near the analyzer/coverage list:

```markdown
- **CORS & client secrets** — a CORS policy allowing any origin *with credentials*
  (FastAPI / Express), and secrets shipped to the browser via `NEXT_PUBLIC_`. A change
  that introduces either is a REVIEW.
```

- [ ] **Step 4: Full verification**

Run: `pytest -q` — Expected: all pass.
Run: `ruff check .` — Expected: no new errors beyond the repo's pre-existing baseline.
Run: `python benchmark/mutation_harness.py` — Expected: every mutation CAUGHT.
Run: `python benchmark/run_precision.py` and `python benchmark/run_eval.py` — Expected: unchanged (1.0/1.0/1.0). **Additionally confirm the new CORS rule does not fire on any precision-corpus fixture** (a false positive there would change the numbers) — if it does, tighten the detector, do not adjust the corpus.

- [ ] **Step 5: Commit**

```bash
git add benchmark/mutation_harness.py README.md
git commit -m "test(web): seed CORS/client-secret fail-open mutations; document coverage"
```

---

## Notes for the executor

- **Precision is cardinal.** Prefer no finding to a false one; if a CORS config or a `NEXT_PUBLIC_` name is ambiguous, emit nothing and note the recall gap.
- Confirm dataclass/field names (`Finding`, `CheckResult`, `Verdict`, `_callable_name`) against source before running each task's tests; adapt the test to the real names, never the reverse.
- Read the raw `source`/`lines` for the JS detectors — the values needed (`origin: "*"`, the `NEXT_PUBLIC_` name) live inside string literals, which the analyzer's `code_lines` view blanks out.
- Do NOT add wildcard-CORS-without-credentials detection, server-import-into-client analysis, a new CLI command, or any dependency — all out of scope (a later slice).
