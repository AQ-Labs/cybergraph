"""The policy/enforcement layer -- CI gate on top of the honest verdict.

Law 7: policy sets the ``gate`` (block/warn/info); it NEVER mutates the
decision. ``gate_for`` is a pure function of ``(verdict, config)`` and never
reads or writes ``verdict.state`` -- no configuration value can launder a
REVIEW into an ACCEPT. This is a separate, enforcement concern from the
DECLARED policy in ``cybergraph.security.policy`` (the login-rule promises a
human wrote): that module answers "what does this application promise?";
this one answers "given the honest verdict, what should CI do about it?".

Both configs happen to live in the same file, ``cybergraph.policy.toml`` --
under a distinct ``[verification]`` table -- because that is the one file a
team already commits and reviews together, not because the two concepts are
the same thing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cybergraph.config import _load_toml
from cybergraph.security.assurance import (
    REASON_CONFIRMED_REGRESSION,
    REASON_UNRESOLVED,
    REASON_UNSUPPORTED,
)
from cybergraph.security.policy import POLICY_FILE
from cybergraph.security.verdict import GATE_BLOCK, GATE_INFO, GATE_WARN, Verdict

# Re-exported, not redefined: ``verdict`` is the single canonical source for
# these three literals (see its module for why -- the import direction can't
# run the other way without a cycle). Existing ``policy_gate.GATE_BLOCK``
# imports elsewhere in the codebase keep working unchanged.
__all__ = [
    "GATE_BLOCK", "GATE_INFO", "GATE_WARN",
    "VerificationConfig", "gate_for", "load_verification_config",
]

_UNKNOWN_CLASSES = (REASON_UNRESOLVED, REASON_UNSUPPORTED)


@dataclass(frozen=True)
class VerificationConfig:
    """What CI enforcement should do with an honest verdict.

    Every default is a policy choice a team can override, never a fact about
    the code -- flipping every one of these off still leaves ``gate_for``
    returning ``warn``/``info`` for a REVIEW, never accept (Law 7).
    """

    block_confirmed_regressions: bool = True
    block_unknown_on_protected_routes: bool = True
    block_general_unknown: bool = False


def gate_for(verdict: Verdict, config: VerificationConfig) -> str:
    """Map a verdict + enforcement config to a CI gate.

    Pure: reads ``verdict.reasons`` and ``config``, returns a string, and
    never touches ``verdict.state``. The order mirrors the severity a team is
    most likely to want blocked by default: a confirmed regression first, then
    an unresolved/unsupported gap on a route the team has declared it cares
    about, then (opt-in only) any other unresolved/unsupported gap. Anything
    left over is advisory -- ``warn`` for a REVIEW, ``info`` for an ACCEPT.
    """
    if config.block_confirmed_regressions and any(
        r.reason_class == REASON_CONFIRMED_REGRESSION for r in verdict.reasons
    ):
        return GATE_BLOCK
    if config.block_unknown_on_protected_routes and any(
        r.reason_class in _UNKNOWN_CLASSES and r.protected for r in verdict.reasons
    ):
        return GATE_BLOCK
    if config.block_general_unknown and any(
        r.reason_class in _UNKNOWN_CLASSES and not r.protected for r in verdict.reasons
    ):
        return GATE_BLOCK
    return GATE_WARN if verdict.reasons else GATE_INFO


def load_verification_config(repo_root: Path) -> VerificationConfig:
    """Read the ``[verification]`` table of ``cybergraph.policy.toml``.

    All-defaults when the file, or the table inside it, is absent -- an
    enforcement config a team never wrote must never silently become
    stricter *or* looser than the documented defaults. Unknown keys are
    ignored (forward compatible); recognised values are coerced to bool
    rather than trusted as already-typed, since TOML lets a human write
    ``"true"`` or ``1`` by mistake.
    """
    path = Path(repo_root) / POLICY_FILE
    if not path.exists():
        return VerificationConfig()

    data = _load_toml(path)
    table = data.get("verification", {})
    if not isinstance(table, dict):
        return VerificationConfig()

    defaults = VerificationConfig()
    return VerificationConfig(
        block_confirmed_regressions=_as_bool(
            table.get("block_confirmed_regressions"), defaults.block_confirmed_regressions
        ),
        block_unknown_on_protected_routes=_as_bool(
            table.get("block_unknown_on_protected_routes"),
            defaults.block_unknown_on_protected_routes,
        ),
        block_general_unknown=_as_bool(
            table.get("block_general_unknown"), defaults.block_general_unknown
        ),
    )


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)
