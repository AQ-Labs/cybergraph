"""Change Assurance Benchmark: patch-pair harness + assurance metric suite.

CyberGraph's product is a verdict on a *change*, not a finding on a file, so the
benchmark that measures it is a patch-pair corpus: a base repo state and the head
state a real change moves it to, each labelled with what the change actually is
(a regression, or not). The runner replays both states through the real
``check_change`` engine in a throwaway git repo and reads back ``verdict.state``.

The governing invariant this benchmark exists to measure: **a false-ACCEPT --
calling a real regression "accept" -- is the cardinal failure.** It is reported
first, labelled primary, in :func:`evaluate`'s output and in
``benchmark/run_precision.py``.

Five metrics are reported, deliberately **not** blended into one score
(:class:`Metrics`). "Compress complexity. Never compress uncertainty": a single
number can hide a false-ACCEPT behind a good precision figure, and this suite
exists specifically so that cannot happen silently.

``ambiguous``-expected cases are excluded from every metric below -- there is no
ground truth to score them against, and folding them into a denominator either
way would quietly assert one.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cybergraph.security.assurance import REASON_CONFIRMED_REGRESSION, REASON_UNSUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_ACCEPT, STATE_REVIEW, Verdict

# --- Case labels ------------------------------------------------------------

EXPECTED_REGRESSION = "regression"
EXPECTED_NO_REGRESSION = "no_regression"
EXPECTED_AMBIGUOUS = "ambiguous"

_VALID_EXPECTED = frozenset({EXPECTED_REGRESSION, EXPECTED_NO_REGRESSION, EXPECTED_AMBIGUOUS})

# Fixed author identity for every seeded commit: deterministic, no dependency
# on the machine's global git config, and never a network call.
_GIT_AUTHOR = ("-c", "user.email=cybergraph-bench@example.com", "-c", "user.name=cybergraph-bench")


@dataclass(frozen=True)
class PatchPairCase:
    """One seeded change: a base repo state and the head state it moves to.

    ``files_a``/``files_head`` map repo-relative paths to full file content.
    Since this harness authors both states itself, "apply the patch" is simply
    "write ``files_head`` over ``files_a``'s checked-out tree, uncommitted" --
    no unified diff, no ``patch(1)``. A path present in ``files_a`` but absent
    from ``files_head`` is deleted when the head state is applied.

    ``vuln_class`` names the case's category (``auth_guard``, ``sql_injection``,
    ``refactor``, ...) for reporting; it is not ``class`` because that word is
    reserved in Python.
    """

    name: str
    files_a: dict[str, str]
    files_head: dict[str, str]
    expected: str
    vuln_class: str
    language: str
    framework: str | None = None

    def __post_init__(self) -> None:
        if self.expected not in _VALID_EXPECTED:
            raise ValueError(f"unrecognized expected value: {self.expected!r}")


def _write_files(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _apply_head_state(root: Path, case: PatchPairCase) -> None:
    _write_files(root, case.files_head)
    for rel in case.files_a:
        if rel not in case.files_head:
            (root / rel).unlink(missing_ok=True)


def build_case_repo(tmp_path: Path, case: PatchPairCase) -> Path:
    """Materialize ``case`` as a temp git repo with the head state left uncommitted.

    The base state is committed to ``main`` as the sole ancestor commit; the
    head state is then written over it and left dirty in the working tree, so
    ``check_change(repo)`` -- called with ``base=None`` -- diffs the working
    tree against ``HEAD``: the same path ``cybergraph .`` takes for a pending,
    uncommitted change.
    """
    repo = tmp_path / case.name
    repo.mkdir(parents=True, exist_ok=True)
    _write_files(repo, case.files_a)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", *_GIT_AUTHOR, "commit", "-qm", "base"], cwd=repo, check=True)
    _apply_head_state(repo, case)
    return repo


def run_patch_pair(case: PatchPairCase, tmp_path: Path) -> Verdict:
    """Build ``case``'s temp repo and return the real ``check_change`` verdict."""
    repo = build_case_repo(tmp_path, case)
    return check_change(repo)


@dataclass(frozen=True)
class CaseOutcome:
    """A scored (expected, actual) pair -- the only shape :func:`evaluate` sees.

    Deliberately engine-agnostic: a hand-built list of ``CaseOutcome`` pins the
    confusion-matrix arithmetic without ever running ``check_change`` (see
    ``tests/test_assurance_metrics.py``). :func:`classify_verdict` is what the
    real patch-pair harness uses to build one from an actual ``Verdict``.
    """

    name: str
    expected: str
    state: str  # STATE_ACCEPT or STATE_REVIEW
    confirmed_regression: bool = False
    unsupported: bool = False

    def __post_init__(self) -> None:
        if self.expected not in _VALID_EXPECTED:
            raise ValueError(f"unrecognized expected value: {self.expected!r}")


def classify_verdict(case: PatchPairCase, verdict: Verdict) -> CaseOutcome:
    """Project a real ``Verdict`` onto the shape :func:`evaluate` scores.

    A REVIEW only counts as a *confirmed* regression call when some reason's
    ``reason_class`` is ``REASON_CONFIRMED_REGRESSION``. A REVIEW driven only
    by ``unresolved``/``unsupported`` reasons is an abstention, not a caught
    regression, even though both read as ``state == STATE_REVIEW``.
    """
    confirmed = any(r.reason_class == REASON_CONFIRMED_REGRESSION for r in verdict.reasons)
    unsupported = any(r.reason_class == REASON_UNSUPPORTED for r in verdict.reasons)
    return CaseOutcome(
        name=case.name,
        expected=case.expected,
        state=verdict.state,
        confirmed_regression=confirmed,
        unsupported=unsupported,
    )


def run_cases(cases: Sequence[PatchPairCase], tmp_path: Path) -> list[CaseOutcome]:
    """Run every case's patch-pair through the real engine and classify it."""
    return [classify_verdict(case, run_patch_pair(case, tmp_path)) for case in cases]


@dataclass(frozen=True)
class Metrics:
    """The assurance metric suite: five figures, never blended into one score.

    No ``score``/``overall``/``grade`` field exists on this dataclass, and
    none should ever be added -- a blended number can hide a false-ACCEPT
    behind a good precision figure, which is exactly the failure this suite
    exists to make visible.

    ``false_accept_rate`` -- **PRIMARY.** The dangerous miss: the fraction of
    real regressions the tool called ACCEPT.
    ``false_accept_rate`` = (# ``expected==regression`` cases ACCEPTed)
                             / (# ``expected==regression`` cases)

    ``recall`` -- the complement, reported explicitly rather than left for the
    reader to compute: ``recall == 1 - false_accept_rate`` over regression
    cases. Both are always printed; neither is allowed to stand alone.
    ``recall`` = (# ``expected==regression`` cases REVIEWed)
                 / (# ``expected==regression`` cases)

    ``review_precision`` -- of everything the tool sent to REVIEW, how much of
    it was a real regression (versus reviewing safe changes needlessly).
    ``review_precision`` = (# REVIEWed cases that were truly ``regression``)
                            / (# REVIEWed cases)
    Guarded against divide-by-zero: 0 reviewed cases -> ``1.0`` (vacuously
    precise -- there is no false review to lower it).

    ``abstention_rate`` -- REVIEW verdicts carrying **no** confirmed-regression
    reason, i.e. driven only by ``unresolved``/``unsupported`` reasons: an
    honest "could not tell" rather than a caught regression.
    ``abstention_rate`` = (# such REVIEW verdicts) / (# cases)

    ``unsupported_rate`` -- cases whose REVIEW is driven by an ``unsupported``
    reason (a change CyberGraph has no analyzer for at all).
    ``unsupported_rate`` = (# such cases) / (# cases)

    All rates are computed over cases with ``expected in
    {regression, no_regression}`` -- ``ambiguous`` cases are excluded from
    every denominator here, not folded into either side.
    """

    false_accept_rate: float
    recall: float
    review_precision: float
    abstention_rate: float
    unsupported_rate: float


def _rate(numerator: int, denominator: int, *, empty: float) -> float:
    return round(numerator / denominator, 4) if denominator else empty


def evaluate(cases: Sequence[CaseOutcome]) -> Metrics:
    """Tally the five-metric assurance suite over ``cases``. See :class:`Metrics`."""
    scored = [c for c in cases if c.expected != EXPECTED_AMBIGUOUS]
    regressions = [c for c in scored if c.expected == EXPECTED_REGRESSION]
    reviewed = [c for c in scored if c.state == STATE_REVIEW]

    missed = [c for c in regressions if c.state == STATE_ACCEPT]
    caught = [c for c in regressions if c.state == STATE_REVIEW]
    true_reviews = [c for c in reviewed if c.expected == EXPECTED_REGRESSION]
    abstentions = [c for c in scored if c.state == STATE_REVIEW and not c.confirmed_regression]
    unsupported_cases = [c for c in scored if c.state == STATE_REVIEW and c.unsupported]

    return Metrics(
        false_accept_rate=_rate(len(missed), len(regressions), empty=0.0),
        recall=_rate(len(caught), len(regressions), empty=1.0),
        review_precision=_rate(len(true_reviews), len(reviewed), empty=1.0),
        abstention_rate=_rate(len(abstentions), len(scored), empty=0.0),
        unsupported_rate=_rate(len(unsupported_cases), len(scored), empty=0.0),
    )


# --- Seed corpus -------------------------------------------------------------
#
# `demos/` (the launch-assets branch) is not on this branch, so these three
# cases are self-contained fixtures reproducing the scenarios it names: an
# auth-guard regression, a tainted-SQL-sink injection, and a policy-preserving
# refactor that must stay `should_accept`.

_AUTH_BASE_APP = '''\
from fastapi import FastAPI, Depends

app = FastAPI()


def require_login():
    return True


@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

_AUTH_HEAD_APP = '''\
from fastapi import FastAPI

app = FastAPI()


def require_login():
    return True


@app.get("/admin/export")
def admin_export():
    return {"ok": True}
'''

_AUTH_POLICY = (
    'version = 1\n\n'
    '[rule.admin]\n'
    'kind = "require_auth"\n'
    'patterns = ["/admin/*"]\n'
    'because = "Admin exports are not public."\n'
)

AUTH_GUARD_REGRESSION = PatchPairCase(
    name="auth_guard_regression",
    files_a={
        "app.py": _AUTH_BASE_APP,
        "cybergraph.policy.toml": _AUTH_POLICY,
    },
    files_head={
        "app.py": _AUTH_HEAD_APP,
        "cybergraph.policy.toml": _AUTH_POLICY,
    },
    expected=EXPECTED_REGRESSION,
    vuln_class="auth_guard",
    language="python",
    framework="fastapi",
)

_SQL_BASE_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
'''

_SQL_HEAD_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return cursor.execute(query)
'''

TAINTED_SQL_INJECTION = PatchPairCase(
    name="tainted_sql_injection",
    files_a={"app.py": _SQL_BASE_APP},
    files_head={"app.py": _SQL_HEAD_APP},
    expected=EXPECTED_REGRESSION,
    vuln_class="sql_injection",
    language="python",
    framework="fastapi",
)

# A plain rename-only case (no web routes at all) is not a fair test of
# "policy-preserving": `declared_login_rules`/`reachable_data_paths` abstain
# with `unresolved` ("no routes to check against") on *any* changed Python
# file when the project declares no routes at all, which would make this
# case REVIEW regardless of what the diff actually does -- an artifact of an
# empty project, not of the refactor. So this case keeps the same
# policy-protected route as `AUTH_GUARD_REGRESSION`'s base (proving the guard
# stays intact) and reorders/renames purely cosmetically around it.
_REFACTOR_BASE_APP = '''\
from fastapi import FastAPI, Depends

app = FastAPI()


def require_login():
    return True


def format_response(payload):
    return {"ok": True, "data": payload}


@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return format_response(None)
'''

# Helper definitions reordered, and a cosmetic parameter/local rename: the
# guard, the route, and the observable behavior are all unchanged.
_REFACTOR_HEAD_APP = '''\
from fastapi import FastAPI, Depends

app = FastAPI()


def format_response(payload):
    return {"ok": True, "data": payload}


def require_login():
    return True


@app.get("/admin/export")
def admin_export(current_user=Depends(require_login)):
    result = format_response(None)
    return result
'''

POLICY_PRESERVING_REFACTOR = PatchPairCase(
    name="policy_preserving_refactor",
    files_a={
        "app.py": _REFACTOR_BASE_APP,
        "cybergraph.policy.toml": _AUTH_POLICY,
    },
    files_head={
        "app.py": _REFACTOR_HEAD_APP,
        "cybergraph.policy.toml": _AUTH_POLICY,
    },
    expected=EXPECTED_NO_REGRESSION,
    vuln_class="refactor",
    language="python",
    framework="fastapi",
)

SEED_CASES: tuple[PatchPairCase, ...] = (
    AUTH_GUARD_REGRESSION,
    TAINTED_SQL_INJECTION,
    POLICY_PRESERVING_REFACTOR,
)
