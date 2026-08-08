# Precision corpus

A labelled corpus of small Python cases, and the gate that decides whether the
verdict predicates in `cybergraph.security.predicates` are actually any good.

`benchmark/run_eval.py` next door measures **reachability** — can CyberGraph get
from an entrypoint to a sink. This one measures **judgement** — given that it
got there, does it say the right thing about the call site.

```bash
python benchmark/run_precision.py     # writes benchmark/precision/results.json
python -m pytest tests/test_precision_gate.py
```

## The four metrics

| Metric | Threshold | Scope |
|---|---|---|
| precision | ≥ 0.90 | gated cases |
| recall | ≥ 0.95 | gated cases, **excluding `known_gap` cases** |
| safe-case **false-positive** rate | ≤ 0.05 | **per vulnerability class** |
| safe-case **abstention** rate | ≤ 0.15 | **per class**, except `command` — measured and reported, not gated |

Three findings during implementation forced this away from a single aggregate
abstention figure. Each is a way the original gate could be passed by a *worse*
tool.

**A single aggregate abstention gate is satisfiable by over-reporting.**
Measured during Task 4: abstention fell 17.6% → 12.9% purely because 23 safe
sites moved from UNKNOWN to *false positive*. The number improved while the tool
got worse. Gating abstention without gating the false-positive rate rewards
exactly the failure this work exists to remove, so both are gated, and both per
class. `tests/test_precision_gate.py::test_trading_abstention_for_false_positives_does_not_improve_the_score`
asserts the trade cannot buy a pass.

**Abstention is workload-dependent, not a detector property.** Measured on real
code: 3.4% on a SQL-heavy repository, 20.0% on a subprocess-heavy one — nearly
all of the latter one irreducible shape, a shell-out to a binary the source does
not name literally. A single aggregate is therefore gameable by corpus
composition: a SQL-heavy corpus passes trivially. The `command` class is exempt
from the abstention gate and carries a stated limitation instead —
**CyberGraph cannot verify a shell-out to a binary that is not named literally**
— while its false-positive rate stays gated.

**An abstention on a safe case is not a true negative.** An earlier revision
excluded `-UNVERIFIED` findings from tp/fp, which is right: penalising an honest
"I could not tell" as a false positive pushes the detector toward guessing. But
a *safe* case that abstained was then scored as a clean pass, while
operationally it produces a REVIEW. You could score perfect precision and recall
while sending every safe change to a human. Abstention is measured and gated
separately, on safe cases, for that reason.

## These thresholds are zero-tolerance at the present corpus size

Read them as **zero**, not as a percentage. The corpus cannot express the
tolerance the numbers imply:

- A class with **three** safe cases can only score a false-positive rate of
  0, 0.33, 0.67 or 1.00. `≤ 0.05` is therefore a **zero-false-positive** gate.
- With **one** safe case (`deserialize`, `interprocedural`) it is 0 or 1.00.
- Abstention `≤ 0.15` is a **zero-abstention** gate on the same counts.
- `recall ≥ 0.95` over **15** unsafe expectations is a **zero-miss** gate:
  14/15 = 0.933 fails.

So every rate is printed with its `n` beside it, and `run_precision.py` marks
any gate computed over fewer than 20 observations `[zero-tolerance at this n]`.
Reporting `FP 0.00 ≤ 0.05 ✓` without `n = 3` beside it claims a tolerance the
corpus cannot express — the same species of overclaim as the headline benchmark
numbers this work exists to correct.

## Current measurement

38 cases, 36 gated, 2 known gaps. Regenerate with `python benchmark/run_precision.py`.

```text
cases=38 gated=36 precision=1.0 (n=15) recall=1.0 (n=15) safe_fp_rate=0.0 safe_abstention_rate=0.0 (safe n=18)
known gaps: 2 (alias_import, from_import)

class              prec    n  recall    n  safeFP    n    abst    n
-------------------------------------------------------------------
code               1.00    2    1.00    2    0.00    2    0.00    2
command            1.00    4    1.00    4    0.00    3    0.00    3 *
deserialize        1.00    1    1.00    1    0.00    1    0.00    1
interprocedural    1.00    1    1.00    1    0.00    1    0.00    1
path               1.00    1    1.00    1    0.00    3    0.00    3
sql                1.00    5    1.00    5    0.00    6    0.00    6
template           1.00    1    1.00    1    0.00    2    0.00    2
* abstention measured but not gated for this class.
```

`n` for precision is `tp + fp`; for recall `tp + fn`; for both safe-case rates
it is the number of safe cases in that class. None of them reaches the
resolution floor of 20, so **every one of these gates is zero-tolerance**.

## Known gaps

`known_gap: true` marks a case **expected to fail today**. Such a case is
excluded from the gated precision and recall figures and **counted and printed
separately** — never silently dropped. Without this the recall gate fails on day
one and the obvious repair, deleting the two cases, destroys the only property
they exist to provide. A corpus containing only cases you already pass measures
nothing.

| Case | Why it fails |
|---|---|
| `alias_import` | `import subprocess as sp` — bare-name resolution cannot follow the alias, so `sp.run` matches no registry entry. |
| `from_import` | `from subprocess import run` — `run` is not a bare sink, and nothing links the unqualified name back to `subprocess.run`. |

Both are real detections a working import-resolution pass would recover.
`tests/test_precision_gate.py::test_known_gaps_are_counted_and_excluded_never_dropped`
asserts they are still present, still failing, and still outside the gated
recall.

## Corpus layout

Each case is `cases/<name>/` with `app.py` and `expected.json`:

```json
{
  "label": "unsafe",
  "vuln_class": "sql",
  "known_gap": false,
  "scoring": "findings",
  "findings": [{"file": "app.py", "line": 13, "rule": "CG-SQL-EXEC"}],
  "abstentions": 0,
  "note": "Composed query text carrying a route parameter."
}
```

`vuln_class` is required: the gate is per class and cannot be computed without
it. `label` is scored on its own terms, because the runner strips `-UNVERIFIED`
findings into an abstention count and a naive comparison would score an
abstention-by-design case as a false negative against its own expectation:

| `label` | passes when |
|---|---|
| `unsafe` | the expected confirmed findings are all present, and nothing else is |
| `safe` | zero confirmed findings **and** zero abstentions |
| `unknown` | the expected abstention count is present; excluded from tp/fp/fn entirely |

### Cases

| Group | Cases |
|---|---|
| SQL unsafe | `sql_concat`, `sql_fstring`, `sql_percent`, `sql_format`, `sql_augassign` |
| SQL safe | `sql_param_qmark`, `sql_param_named`, `sql_constant`, `sql_hoisted_constant`, `sql_composed_clean`, `sql_reassigned_after_call` |
| SQL unknown | `sql_via_builder` |
| Command unsafe | `cmd_shell_true`, `cmd_fstring_shell_true`, `cmd_sh_dash_c`, `cmd_tainted_argv0` |
| Command safe | `cmd_list_args`, `cmd_list_shell_false`, `cmd_constant` |
| Command unknown | `cmd_string_no_shell` |
| Path | `path_direct` (unsafe), `path_basename`, `path_safe_join`, `path_constant` (safe), `path_normpath` (unknown) |
| Deserialize | `pickle_tainted` (unsafe), `yaml_safe_load` (safe) |
| Template | `template_string_tainted` (unsafe), `template_render_context`, `template_constant` (safe) |
| Code | `eval_tainted`, `exec_tainted` (unsafe), `literal_eval`, `eval_constant` (safe) |
| Imports | `alias_import`, `from_import` (unsafe, known gaps) |
| Interprocedural | `cross_function` (unsafe), `sanitized_helper` (safe) |

`Template` and `Code` are here because the gate is **per class** and
`_assess_template` and `_assess_code` are two of the six predicates. Without
them those classes would carry no cases and their false-positive gate would
silently never apply — the same "a corpus containing only cases you already pass
measures nothing" failure, arrived at by omission instead of by choosing easy
cases.

`sql_reassigned_after_call` is the flow-sensitivity regression from Task 3: a
whole-function binding map would let an assignment *after* the call reach back
into it.

## Two things the corpus does not measure, stated plainly

**The `interprocedural` cases are scored on attack paths, not findings.**
Findings are intra-procedural, so a helper that receives user data as an
ordinary parameter carries no taint of its own: `cross_function` legitimately
yields **zero findings** while its entrypoint→sink path is perfectly correct.
The same is true of `py_fastapi_cmdi`, `_pathtrav` and `_sqli` in the
reachability corpus next door. (`min_findings` in `benchmark/cases/*/expected.json`
is dead metadata — present in nine cases, read by nothing — and is not a
contract.) A path crossing a sanitiser is not counted as a detection, which is
what makes `sanitized_helper` a safe case: the path exists as inventory and
carries `sanitized: true`. Attack paths have no `-UNVERIFIED` equivalent, so
**abstention is not observable on these two cases** and is recorded as 0.

**Three safe cases exercise the sink registry rather than a predicate.**
`yaml_safe_load`, `literal_eval` and the `render_template` call inside
`template_render_context` name APIs that are deliberately *not* in
`cybergraph.security.sinks`, so no predicate runs for them at all. They are
real regression guards — they would fail if someone re-introduced substring
matching on `eval` or `load` — but they do not exercise
`_assess_any_tainted_argument` or `_assess_template`. Consequences:

- `deserialize` has **one** safe case and it is of this kind, so the
  `deserialize` safe-case false-positive gate is currently **vacuous**. Adding a
  `pickle.loads(<literal>)` safe case would fix it.
- `code` and `template` are covered, because `eval_constant` and the
  `render_template_string("<h1>Hello {{ name }}</h1>", name=name)` line in
  `template_render_context` do reach their predicates.

Both `code` and `template` safe cases are written with **literal** arguments on
purpose. `_assess_any_tainted_argument` returns `unknown` for any non-`Constant`
argument that classifies OPAQUE, so `eval("6 * 7")` scores `safe` while
`eval(EXPRESSION)` against a module-level constant scores `unknown` — an
abstention, gated at zero tolerance. Writing those cases the other way would
fail the gate on case authoring rather than on detector behaviour.

## Open defect N-1: the false-positive figures do not cover it

*Recorded 2026-08-08, confirmed by execution, fix owned elsewhere.*

`provenance.py::user_input_nodes` introduces taint by **substring**-matching a
dotted chain against `SOURCE_KEYWORDS`. It excludes a bare `ast.Name`, but
accepts any Attribute/Call/Subscript whose chain text merely *contains*
`input`, `body`, `params`, `query`, `form`, `cookie`, `request`, `headers`,
`argv` or `webhook`. Any member with such a name becomes a taint source. It is
the same defect class this work exists to remove from sink matching,
reintroduced on the source side. Measured:

```text
subprocess.run("ls " + cfg.input_dir, shell=True)   -> CG-CMD-EXEC       critical  (false positive)
open(args.input)                                    -> CG-PATH-TRAVERSAL high      (false positive)
open(self.input_path)                               -> CG-PATH-TRAVERSAL high      (false positive)
cursor.execute(f"select {self.query}")              -> CG-SQL-EXEC       high      (false positive)
pickle.loads(session.cookie_jar)                    -> CG-DESERIALIZE    critical  (false positive)
open(p.path)                                        -> no finding                  (control)
```

**Say the quiet part: this corpus does not exercise that path at all.** Every
taint fact in all 38 cases arrives through a *route parameter*, seeded
structurally by `analysis.python._route_inputs`. Running `user_input_nodes`
over every call in every `app.py` returns **zero** matches, so the safe-case
false-positive rates of `0.00` above are measured entirely on the structural
taint path and say nothing whatever about N-1. The `0.00` is real for what it
covers and the coverage is narrower than the number looks.

No case was renamed or reworded to avoid this — the names in the corpus
(`name`, `revision`, `term`, `host`, `DATA_DIR`) were chosen before N-1 was
known — but the effect is the same as if they had been, and a gate that passes
by corpus composition is worth nothing. Once N-1 is fixed, a case of the shape
`open(args.input)` where `args` is a local config object should be added as a
**safe** `path` case; it fails today, and it is the case that would have caught
this.

## Governing invariant

**Uncertainty never becomes safety.** Three verdicts — `safe`, `unsafe`,
`unknown` — and an abstention carries the sink's rule id with a `-UNVERIFIED`
suffix at reduced severity. A wrong `safe` is worse than a false positive.
Scoring must never reward guessing, which is why an abstention is excluded from
tp/fp *and* gated separately on safe cases.
