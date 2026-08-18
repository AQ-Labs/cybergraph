"""Task 10: adversarial Patch-to-Pass harness -- P0A / Law 6.

CyberGraph's verdict must resist gaming on the vectors where gaming is not
fixing: an alternate *construction* of the exact same tainted SQL query, or a
"sanitizer" that is a barrier in name only. Neither actually removes the
vulnerability, so neither may flip a REVIEW verdict to ACCEPT -- doing so
would be the cardinal failure this suite exists to catch (uncertainty/danger
must never become safety).

Every case here is run against the REAL ``check_change`` engine over a throw-
away git repo (no mocks). Where a construction is found to genuinely slip
past the engine today, it is recorded in ``KNOWN_GAPS`` rather than hidden:
the suite stays green against that honest baseline, but goes red the moment
a NEW/unrecorded construction flips (a regression) or a recorded gap starts
being caught (so the backlog shrinks visibly instead of silently).
"""

from __future__ import annotations

import sys
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK_DIR))

from patch_to_pass import (  # noqa: E402
    EVASIONS,
    GENUINE_FIX_CASE,
    IDENTITY_SANITIZER_CASE,
    KNOWN_GAPS,
    _flips_to_accept,
)


def test_genuine_fix_flips_to_accept(tmp_path):
    """Non-vacuity control: a real fix (taint actually removed) MUST flip.

    Without this, "no adversarial case flips" is indistinguishable from "no
    case can ever flip" -- e.g. some unrelated reason forcing every verdict
    in this module to REVIEW regardless of what the SQL detector found. This
    proves ACCEPT is genuinely reachable, so the two tests below are
    evidence the evasions/sanitizer were caught, not an artifact of a
    structurally-unreachable ACCEPT branch.
    """
    assert _flips_to_accept(tmp_path, GENUINE_FIX_CASE) is True


def test_detector_evasion_does_not_flip_review_to_accept(tmp_path):
    """Same tainted SQL, alternate construction -- must still REVIEW.

    A recorded ``KNOWN_GAPS`` entry is the only way a construction is allowed
    to flip; everything else must stay REVIEW.
    """
    for name, construction in EVASIONS.items():
        flipped = _flips_to_accept(tmp_path, construction)
        if name in KNOWN_GAPS:
            assert flipped, (
                f"{name!r} is recorded in KNOWN_GAPS as flipping to ACCEPT, but it "
                "did not -- the backlog entry is stale and must be removed."
            )
        else:
            assert not flipped, (
                f"{name!r} flipped a genuinely-tainted SQL query's verdict from "
                "REVIEW to ACCEPT. This is a false-ACCEPT gap: record it in "
                "KNOWN_GAPS with a note, or fix the classifier."
            )


def test_name_only_sanitizer_does_not_manufacture_safe(tmp_path):
    """``def sanitize(x): return x`` must not manufacture a clean verdict.

    The identity function does nothing -- the taint is exactly as present
    after it as before. A barrier that exists only in name must not be
    trusted as though it were real.
    """
    flipped = _flips_to_accept(tmp_path, IDENTITY_SANITIZER_CASE)
    if "identity_sanitizer" in KNOWN_GAPS:
        assert flipped, (
            "'identity_sanitizer' is recorded in KNOWN_GAPS as flipping to ACCEPT, "
            "but it did not -- the backlog entry is stale and must be removed."
        )
    else:
        assert not flipped, (
            "A name-only identity sanitizer manufactured a SAFE verdict for a "
            "still-tainted SQL sink. This is a false-ACCEPT gap: record it in "
            "KNOWN_GAPS with a note, or fix the classifier."
        )
