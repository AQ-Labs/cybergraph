"""Epistemic vocabulary, trust composition, and claim-language rules.

This module is the single source of truth for how CyberGraph talks about
what it knows. It enforces two of the project's Seven Laws:

- Law 1: presentation may never strengthen a finding's epistemic status.
  See ``FORBIDDEN_ON_UNCONFIRMED`` and ``has_epistemic_upgrade``.
- Law 3: trust composes to the weaker of evidence-strength and
  capability-assurance; no invented numeric confidence is produced here.
  See ``effective_trust``.

Pure, dependency-free: stdlib only, no imports from the rest of the
codebase. Later tasks build on the vocabulary defined here.
"""

from __future__ import annotations

# --- Evidence strength -------------------------------------------------
EVIDENCE_STRONG = "strong"
EVIDENCE_PARTIAL = "partial"
EVIDENCE_WEAK = "weak"
EVIDENCE_NONE = "none"

# --- Capability assurance -----------------------------------------------
ASSURANCE_BENCHMARKED = "benchmark_backed"
ASSURANCE_BETA = "beta"
ASSURANCE_INVENTORY = "inventory"
ASSURANCE_UNSUPPORTED = "unsupported"

# --- Finding status -------------------------------------------------------
STATUS_CONFIRMED = "confirmed"
STATUS_UNRESOLVED = "unresolved"
STATUS_UNSUPPORTED = "unsupported"

# --- Reason codes ---------------------------------------------------------
REASON_CONFIRMED_REGRESSION = "confirmed_regression"
REASON_UNRESOLVED = "unresolved"
REASON_UNSUPPORTED = "unsupported"

# --- Ordered trust scale ---------------------------------------------------
# Positional pairing: evidence and assurance share tiers by index.
# Index 0 is the weakest tier, index 3 is the strongest.
_EVIDENCE_SCALE = (EVIDENCE_NONE, EVIDENCE_WEAK, EVIDENCE_PARTIAL, EVIDENCE_STRONG)
_ASSURANCE_SCALE = (
    ASSURANCE_UNSUPPORTED,
    ASSURANCE_INVENTORY,
    ASSURANCE_BETA,
    ASSURANCE_BENCHMARKED,
)


def _tier(value: str) -> int:
    """Return the 0-3 tier index for an evidence or assurance value."""
    if value in _EVIDENCE_SCALE:
        return _EVIDENCE_SCALE.index(value)
    if value in _ASSURANCE_SCALE:
        return _ASSURANCE_SCALE.index(value)
    raise ValueError(f"unrecognized evidence/assurance value: {value!r}")


def effective_trust(evidence: str, assurance: str) -> str:
    """Compose evidence strength and capability assurance to the weaker tier.

    Trust never exceeds the weaker of the two inputs (Law 3). Ties are
    broken in favor of the evidence value.
    """
    evidence_tier = _tier(evidence)
    assurance_tier = _tier(assurance)
    if evidence_tier <= assurance_tier:
        return evidence
    return assurance


def phrase_for(status: str, evidence: str, assurance: str) -> str:
    """Return the one claim-language phrase warranted by these inputs.

    Cardinal rule: "confirmed" is permitted ONLY when status is
    STATUS_CONFIRMED AND evidence is EVIDENCE_STRONG AND assurance is
    ASSURANCE_BENCHMARKED. Every other combination is graded down so
    presentation never outruns what was actually established (Law 1).
    """
    if status == STATUS_UNSUPPORTED:
        return "not evaluated"
    if status == STATUS_UNRESOLVED:
        return "could not verify"
    # status == STATUS_CONFIRMED from here on.
    if evidence == EVIDENCE_STRONG and assurance == ASSURANCE_BENCHMARKED:
        return "confirmed"
    return "possible"


# --- Law 1 lint: forbidden language on unconfirmed findings ---------------
FORBIDDEN_ON_UNCONFIRMED: frozenset[str] = frozenset(
    {
        "confirmed",
        "is vulnerable",
        "will",
        "can be exploited",
        "exploitable",
        "breach",
    }
)


def has_epistemic_upgrade(text: str, status: str) -> bool:
    """Detect language that overstates confidence relative to ``status``.

    Case-insensitive substring scan against ``FORBIDDEN_ON_UNCONFIRMED``.
    Always False when ``status == STATUS_CONFIRMED`` — those phrases are
    warranted once a finding is actually confirmed.
    """
    if status == STATUS_CONFIRMED:
        return False
    lowered = text.lower()
    return any(phrase in lowered for phrase in FORBIDDEN_ON_UNCONFIRMED)
