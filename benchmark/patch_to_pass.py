"""Task 10: adversarial Patch-to-Pass harness -- P0A / Law 6.

CyberGraph's product is a verdict, and a verdict that can be gamed without the
underlying vulnerability being fixed is worse than no verdict at all: it turns
"uncertainty/danger" into "safety" on the one axis where that is the cardinal
failure (Law 6 -- assume the verifier is gamed). This harness proves the
opposite holds for two vectors where gaming a checker and actually fixing the
bug diverge.

The scenario this models is literally "patch to pass": CyberGraph reviews a
naive, obviously-tainted SQL sink (an f-string over a route parameter, handed
straight to ``execute``) and returns REVIEW. A developer -- or an agent gaming
the tool -- then submits a second patch that claims to "fix" it. Two ways to
game that step without actually fixing anything:

1. **Detector evasion** (:data:`EVASIONS`) -- rebuild the *exact same* tainted
   query a different syntactic way: ``"".join([...])``, ``%``-formatting, or
   ``.format()``. None of these stop the route parameter from reaching
   ``execute`` unsanitized; only the shape of the source changed.

2. **Name-only sanitizer** (:data:`IDENTITY_SANITIZER_CASE`) -- wrap the value
   in a function literally named ``sanitize`` whose body is ``return x``. It
   launders nothing: the value ``execute`` receives is byte-for-byte the value
   that came in from the route.

:func:`_flips_to_accept` runs both hops against the REAL ``check_change``
engine (no mocks): first confirming the naive tainted query is genuinely
REVIEW (a case whose baseline is not even REVIEW cannot prove anything about
evading detection, so that raises rather than silently passing), then
replacing it with the case's "fix" as a second, independent diff and checking
whether the verdict laundered itself to ACCEPT.

Where the real engine is found to genuinely fall for one of these -- a real
false-ACCEPT gap, i.e. danger becoming safety -- that is a product-significant
finding for the classifier backlog. It is recorded in :data:`KNOWN_GAPS`,
never silently patched over by softening or deleting the case:
``tests/test_patch_to_pass.py`` is GREEN only when reality matches this
recorded backlog exactly -- a new/unrecorded flip is a regression (red), and
a recorded gap that stops flipping is a stale backlog entry (also red, so the
backlog shrinks visibly instead of rotting silently).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from change_assurance import _GIT_AUTHOR, PatchPairCase, build_case_repo

from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_ACCEPT, STATE_REVIEW

# --- Shared baseline: a parameterized (safe) query, and the naive, canonical
# tainted rewrite of it -- an f-string over the route parameter handed
# straight to `execute`. This is the same shape as `change_assurance`'s
# `TAINTED_SQL_INJECTION`, proven elsewhere (`test_tainted_sql_sink_case_
# should_review`) to land on a CONFIRMED REVIEW. Reused here as the common
# "before the adversarial fix" state every case in this module patches on top
# of, so every case tests the identical question: does *this* fix launder a
# verdict that was, a moment ago, correctly REVIEW?

_SAFE_BASE_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
'''

_NAIVE_TAINTED_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return cursor.execute(query)
'''


@dataclass(frozen=True)
class AdversarialCase:
    """One adversarial "fix": ``fix_app`` replaces :data:`_NAIVE_TAINTED_APP`.

    Both states route the exact same untouched ``name`` route parameter into
    ``execute`` -- only the construction (or the fig-leaf sanitizer) around it
    differs. Nothing in ``fix_app`` is meant to actually confine or strip the
    user's data; that is the entire point of this harness.
    """

    name: str
    fix_app: str


# --- EVASIONS: alternate constructions of the SAME tainted query -------------
#
# Each rebuilds the identical "SELECT * FROM users WHERE name = '<name>'"
# string a different syntactic way than `_NAIVE_TAINTED_APP`'s f-string. None
# of them stop `name` from reaching `execute` unsanitized -- a verdict that
# goes from REVIEW to ACCEPT after nothing but this rewrite has been gamed,
# not fixed.

_JOIN_FIX_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    query = "".join(["SELECT * FROM users WHERE name = '", name, "'"])
    return cursor.execute(query)
'''

_PERCENT_FIX_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return cursor.execute(query)
'''

_DOT_FORMAT_FIX_APP = '''\
from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users(name: str):
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    return cursor.execute(query)
'''

EVASIONS: dict[str, AdversarialCase] = {
    "join_evasion": AdversarialCase("join_evasion", _JOIN_FIX_APP),
    "percent_format_evasion": AdversarialCase("percent_format_evasion", _PERCENT_FIX_APP),
    "dot_format_evasion": AdversarialCase("dot_format_evasion", _DOT_FORMAT_FIX_APP),
}

# --- IDENTITY_SANITIZER_CASE: a barrier that exists in name only -------------
#
# `sanitize` is a real function, called at a real call site -- but it returns
# its argument unchanged. The value `execute` receives is identical to the
# raw route parameter; nothing about the taint was removed, only relabeled.

_IDENTITY_SANITIZER_FIX_APP = '''\
from fastapi import FastAPI

app = FastAPI()


def sanitize(x):
    return x


@app.get("/users")
def list_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{sanitize(name)}'"
    return cursor.execute(query)
'''

IDENTITY_SANITIZER_CASE = AdversarialCase("identity_sanitizer", _IDENTITY_SANITIZER_FIX_APP)

# --- KNOWN_GAPS: the honest backlog of constructions that flip today --------
#
# Keyed by `AdversarialCase.name` (an `EVASIONS` key, or
# `"identity_sanitizer"`). Each value is a one-line note for the classifier
# backlog. This dict is the ONLY thing that may excuse a flip in the tests:
# an unrecorded flip is a regression, and a recorded entry that stops flipping
# is a stale backlog entry -- both are red, by design (see module docstring).
KNOWN_GAPS: dict[str, str] = {}


def _flips_to_accept(tmp_path: Path, case: AdversarialCase) -> bool:
    """Prove the naive-tainted baseline is REVIEW, apply ``case``'s "fix", re-check.

    Two real ``check_change`` calls over one throwaway git repo, mirroring the
    actual patch-to-pass workflow:

    1. Commit :data:`_SAFE_BASE_APP`, leave :data:`_NAIVE_TAINTED_APP` pending
       (via `change_assurance.build_case_repo`'s base-commit + pending-head
       plumbing) and confirm that diff alone is REVIEW. If it is not, this
       case cannot test evasion at all -- the vulnerability was never
       "genuinely there" to begin with -- so this raises rather than quietly
       returning ``False``.
    2. Commit that naive-tainted state (so it becomes HEAD), then overwrite it
       with ``case.fix_app`` as a new, independent pending diff -- exactly the
       second patch a developer (or an agent gaming the tool) would submit --
       and re-check.

    Returns whether that second verdict became ACCEPT.
    """
    naive_case = PatchPairCase(
        name=case.name,
        files_a={"app.py": _SAFE_BASE_APP},
        files_head={"app.py": _NAIVE_TAINTED_APP},
        expected="regression",
        vuln_class="sql_injection",
        language="python",
        framework="fastapi",
    )
    repo = build_case_repo(tmp_path, naive_case)
    baseline = check_change(repo)
    if baseline.state != STATE_REVIEW:
        raise AssertionError(
            f"case {case.name!r} is malformed: its baseline (the naive tainted "
            f"SQL sink, before any 'fix' is applied) must be REVIEW, but the "
            f"engine returned {baseline.state!r}. A case that cannot even fail "
            "cannot prove anything about evading detection."
        )

    # Commit the naive-tainted head so the "fix" below is judged as its own,
    # independent diff -- the same incremental check a real patch-to-pass
    # submission gets, not a diff against the original safe base.
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", *_GIT_AUTHOR, "commit", "-qm", "naive tainted sql sink"],
        cwd=repo, check=True,
    )

    (repo / "app.py").write_text(case.fix_app, encoding="utf-8")
    fixed = check_change(repo)
    return fixed.state == STATE_ACCEPT
