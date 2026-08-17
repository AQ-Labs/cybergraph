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

import re

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


# --- Assurance matrix: today's honest maturity map ------------------------
# Capability ids that produce verdicts today via per-language injection
# analyzers (SQL/command/code-execution/deserialization/path). These match
# the ids in cybergraph.security.capability.CAPABILITIES, duplicated as
# literals here rather than imported -- this module stays dependency-free
# (see module docstring).
_INJECTION_CAPABILITIES: frozenset[str] = frozenset(
    {
        "sql_construction",
        "command_execution",
        "code_execution",
        "deserialization",
        "path_access",
    }
)

# Other capability.py ids: posture/coverage capabilities that exist but do
# not carry a per-language injection-verdict maturity story.
_NON_INJECTION_CAPABILITIES: frozenset[str] = frozenset(
    {
        "declared_login_rules",
        "reachable_data_paths",
        "source_analysis_support",
        "client_secret_boundary",
        "cloud_configuration",
        "cross_origin_policy",
    }
)

# Python frameworks (or none declared) whose injection analysis is actually
# benchmarked today.
_PYTHON_BENCHMARKED_FRAMEWORKS: frozenset[str | None] = frozenset(
    {"fastapi", "flask", "django", None}
)

# Other languages with an injection analyzer, but not yet benchmarked --
# every injection capability is beta for each of these regardless of
# framework.
_BETA_LANGUAGES: frozenset[str] = frozenset(
    {"javascript", "typescript", "go", "java", "csharp"}
)

# capability_id -> language -> assurance tier, for the injection
# capabilities only. This is today's honest maturity map, not an
# aspiration: only Python on a benchmarked framework reaches
# ASSURANCE_BENCHMARKED (handled separately in ``assurance_for``); every
# other language known to have an analyzer defaults to ASSURANCE_BETA here.
_MATRIX: dict[str, dict[str, str]] = {
    capability_id: dict.fromkeys(_BETA_LANGUAGES, ASSURANCE_BETA)
    for capability_id in _INJECTION_CAPABILITIES
}


def assurance_for(capability_id: str, language: str | None, framework: str | None) -> str:
    """Return the ASSURANCE_* tier for a capability/language/framework cell.

    Conservative by construction (Law 3): ASSURANCE_BENCHMARKED is reached
    only by Python on a framework CyberGraph has actually benchmarked its
    injection analyzers against. Every other cell is graded down --
    other-language injection analyzers to ASSURANCE_BETA, non-injection
    capabilities to ASSURANCE_INVENTORY, and anything unrecognized to
    ASSURANCE_UNSUPPORTED. Unknown languages never upgrade a cell; they can
    only ever land on ASSURANCE_BETA at best.
    """
    if capability_id in _INJECTION_CAPABILITIES:
        if language == "python":
            if framework in _PYTHON_BENCHMARKED_FRAMEWORKS:
                return ASSURANCE_BENCHMARKED
            return ASSURANCE_BETA
        return _MATRIX[capability_id].get(language, ASSURANCE_BETA)
    if capability_id in _NON_INJECTION_CAPABILITIES:
        return ASSURANCE_INVENTORY
    return ASSURANCE_UNSUPPORTED


# --- Law 1 lint: forbidden language on unconfirmed findings ---------------
# Word-stems rather than exact phrases, so natural paraphrases ("appears
# vulnerable", "was exploited", "can compromise") are caught, not just the
# literal phrases below. Kept here (not just in the regex) as the readable
# source of truth for what "confirmed-sounding" means.
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

# Stems matched with a trailing \w* so conjugations/derivations count too:
# "vulnerab" -> vulnerable, vulnerability; "exploit" -> exploited,
# exploitable, exploits; "compromis" -> compromise, compromised,
# compromising; "confirm" -> confirmed, confirms; "breach" -> breached,
# breaches.
_FORBIDDEN_STEMS: tuple[str, ...] = ("confirm", "vulnerab", "exploit", "compromis", "breach")

# Matched as a whole word only (no stemming) -- "will" must not fire on
# "willow" or "goodwill".
_FORBIDDEN_WORDS: tuple[str, ...] = ("will",)

_FORBIDDEN_PATTERN = re.compile(
    r"\b(?:" + "|".join(_FORBIDDEN_STEMS) + r")\w*\b"
    r"|\b(?:" + "|".join(_FORBIDDEN_WORDS) + r")\b",
    re.IGNORECASE,
)


def has_epistemic_upgrade(text: str, status: str) -> bool:
    """Detect language that overstates confidence relative to ``status``.

    Word-boundary, case-insensitive match against confirmed-sounding
    stems/words (see ``_FORBIDDEN_PATTERN``). Always False when
    ``status == STATUS_CONFIRMED`` — those phrases are warranted once a
    finding is actually confirmed. Missing a real upgrade is the dangerous
    direction, so this errs toward flagging paraphrases.
    """
    if status == STATUS_CONFIRMED:
        return False
    return bool(_FORBIDDEN_PATTERN.search(text))
