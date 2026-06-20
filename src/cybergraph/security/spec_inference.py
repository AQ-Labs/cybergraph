"""LLM-inferred taint specs (opt-in, validated, default-off).

CyberGraph's analyzers recognize sinks/sources/sanitizers/secrets from fixed
keyword tables in :mod:`cybergraph.security.ontology`. Real codebases wrap those
behaviors behind project-specific names (``run_report_sql``, ``fetch_remote``,
``scrub_html``) that the tables miss. This module lets an LLM widen coverage by
proposing which of the repo's ACTUAL called functions look security-sensitive —
then validates every proposal against program facts before trusting it.

Determinism principle (AdaTaint): the LLM proposes, the graph + ontology dispose.
A proposed name is accepted only if it is

  (a) **grounded** — it really appears among the repo's call sites (no
      hallucinated APIs), and
  (b) **novel** — not already covered by the relevant ontology table (otherwise
      it adds nothing).

Accepted specs map onto the analyzers' existing ``custom_sinks`` / ``*_markers``
extension points, so nothing in the analyzers changes. Nothing here runs unless a
caller passes a client: with ``client is None`` it abstains and returns empty
specs, leaving the deterministic pipeline untouched.

Research basis: LLM-inferred taint specifications validated before use (IRIS,
ICLR'25) grounded in program facts rather than the model alone (AdaTaint).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from cybergraph.analysis.resolve import _simple_name
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import (
    SECRET_KEYWORDS,
    SINK_KEYWORDS,
    SOURCE_KEYWORDS,
    VALIDATION_KEYWORDS,
)

# Category -> ontology table the proposal must be NOVEL against.
CATEGORY_TABLES: dict[str, set[str]] = {
    "sink": SINK_KEYWORDS,
    "source": SOURCE_KEYWORDS,
    "sanitizer": VALIDATION_KEYWORDS,
    "secret": SECRET_KEYWORDS,
}

_SYSTEM = (
    "You are a security taint-specification assistant. You are given the list of "
    "function names actually CALLED in a codebase. Identify which of those names "
    "denote security-sensitive behavior that a taint analyzer should track, and "
    "classify each as one of: sink (dangerous operation: SQL/shell/file/network/"
    "deserialization), source (untrusted input), sanitizer (validates/escapes/"
    "neutralizes input), or secret (handles credentials/keys). Choose ONLY from the "
    "provided names — never invent names. Respond with STRICT JSON: "
    '{"sinks": [str], "sources": [str], "sanitizers": [str], "secrets": [str]}. '
    "Omit names that are ordinary, non-security functions."
)


@dataclass(frozen=True)
class InferredSpecs:
    """Validated, ready-to-use taint specs plus rejected proposals (provenance)."""

    sinks: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    rejected: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total_accepted(self) -> int:
        return len(self.sinks) + len(self.sources) + len(self.sanitizers) + len(self.secrets)


def candidate_calls(repo_root: Path) -> list[str]:
    """Return the distinct simple names of functions actually called in the repo.

    This is the grounding set: a proposal is trusted only if it appears here.
    """
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        rows = store.conn.execute(
            "SELECT DISTINCT target FROM edges WHERE kind = 'CALLS'"
        ).fetchall()
    finally:
        store.close()
    names = {_simple_name(r["target"]).lower() for r in rows if r["target"]}
    names.discard("")
    return sorted(names)


def _is_known(name: str, table: set[str]) -> bool:
    """True if any ontology keyword is already a substring of ``name`` (covered)."""
    low = name.lower()
    return any(kw in low for kw in table)


def _is_grounded(name: str, call_set: set[str]) -> bool:
    """True if ``name`` overlaps a real call name (either direction of substring)."""
    low = name.lower()
    return any(low == c or low in c or c in low for c in call_set)


def _parse_proposals(raw: str) -> dict[str, list[str]]:
    """Parse the model's JSON; on any trouble return empty proposals (abstain)."""
    match = re.search(r"\{.*\}", raw or "", re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except (TypeError, ValueError):
        return {}
    out: dict[str, list[str]] = {}
    for cat in CATEGORY_TABLES:
        values = data.get(f"{cat}s", [])
        if isinstance(values, list):
            out[cat] = [str(v).strip() for v in values if str(v).strip()]
    return out


def validate_proposals(
    proposals: dict[str, list[str]], calls: list[str]
) -> InferredSpecs:
    """Keep only proposals that are grounded in real calls AND novel vs. the ontology.

    This is the guardrail: hallucinated names (not in ``calls``) and names already
    covered by a keyword table are rejected, so the analyzer never widens its taint
    surface on an unverifiable guess.
    """
    call_set = {c.lower() for c in calls}
    accepted: dict[str, list[str]] = {cat: [] for cat in CATEGORY_TABLES}
    rejected: list[str] = []
    for cat, table in CATEGORY_TABLES.items():
        for name in proposals.get(cat, []):
            if not _is_grounded(name, call_set):
                rejected.append(f"{name} ({cat}: not found in call sites)")
            elif _is_known(name, table):
                rejected.append(f"{name} ({cat}: already covered by ontology)")
            elif name.lower() in accepted[cat]:
                continue
            else:
                accepted[cat].append(name.lower())
    return InferredSpecs(
        sinks=tuple(accepted["sink"]),
        sources=tuple(accepted["source"]),
        sanitizers=tuple(accepted["sanitizer"]),
        secrets=tuple(accepted["secret"]),
        rejected=tuple(rejected),
    )


def propose_specs(
    repo_root: Path,
    client=None,
    calls: list[str] | None = None,
) -> InferredSpecs:
    """Infer taint specs for a repo. ``client is None`` -> abstain (empty specs).

    With a client, the repo's real call names are sent to the model, its proposals
    are parsed, and every proposal is run through :func:`validate_proposals` before
    it is returned.
    """
    if client is None:
        return InferredSpecs()
    if calls is None:
        calls = candidate_calls(Path(repo_root).resolve())
    if not calls:
        return InferredSpecs()
    user = (
        "CALLED FUNCTION NAMES:\n"
        + ", ".join(calls)
        + '\n\nReturn STRICT JSON {sinks, sources, sanitizers, secrets} using ONLY '
        "names from the list above."
    )
    try:
        raw = client.complete(_SYSTEM, user)
    except Exception:  # never let an LLM error widen or break analysis; abstain
        return InferredSpecs()
    return validate_proposals(_parse_proposals(raw), calls)


def format_specs(specs: InferredSpecs) -> str:
    """Human-readable summary plus a ready-to-paste config snippet."""
    if specs.total_accepted == 0:
        head = "No new taint specs inferred (none grounded + novel)."
    else:
        head = f"Inferred {specs.total_accepted} validated taint spec(s):"
    lines = [head]
    for label, values in (
        ("sinks", specs.sinks),
        ("sources", specs.sources),
        ("sanitizers", specs.sanitizers),
        ("secrets", specs.secrets),
    ):
        if values:
            lines.append(f"  {label}: {', '.join(values)}")
    if specs.rejected:
        lines.append(f"  rejected {len(specs.rejected)} proposal(s) by validation:")
        for r in specs.rejected[:10]:
            lines.append(f"    - {r}")
    if specs.sinks:
        lines.append("")
        lines.append("Add to .cybergraph.toml to enable on the next build:")
        lines.append("  [security]")
        lines.append(f"  sinks = {list(specs.sinks)!r}")
    return "\n".join(lines)
