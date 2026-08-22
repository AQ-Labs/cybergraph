"""Render the declared policy and what it protects, as a read-only report.

Assembly is separated from the CLI so a later verdict/MCP surface can reuse it.
This makes no accept/block decision: policy problems are reported, never turned
into a verdict here.
"""

from __future__ import annotations

from datetime import date

from cybergraph.config import CyberGraphConfig
from cybergraph.security.policy import Policy, ProtectedSet
from cybergraph.suppressions import suppression_problems


def format_policy_report(
    policy: Policy,
    protected_set: ProtectedSet,
    config: CyberGraphConfig | None = None,
    today: date | None = None,
) -> str:
    lines: list[str] = []
    if not policy.exists:
        lines.append("No policy declared (cybergraph.policy.toml absent).")
    else:
        count = len(policy.rules)
        suffix = "" if count == 1 else "s"
        lines.append(f"Policy: cybergraph.policy.toml ({count} rule{suffix})")
        for rule in policy.rules:
            lines.append(f"  {rule.id}  {rule.kind}  {', '.join(rule.patterns)}")

    if policy.problems:
        lines.append("")
        lines.append(f"Policy problems: {len(policy.problems)}")
        for problem in policy.problems:
            lines.append(f"  ! {problem.rule_id}: {problem.message}")

    if config is not None:
        problems = suppression_problems(config, today)
        if problems:
            lines.append("")
            lines.append(f"Suppression problems: {len(problems)}")
            for problem in problems:
                entry = next(
                    (
                        s
                        for s in config.suppressions
                        if s.kind == problem.kind and s.matcher == problem.matcher
                    ),
                    None,
                )
                suffix = ""
                if entry is not None and entry.approver:
                    suffix = f"  (approver: {entry.approver})"
                lines.append(f"  ! {problem.matcher}: {problem.message}{suffix}")

    unprotected = protected_set.unprotected
    lines.append("")
    lines.append(
        f"Protected entities: {len(protected_set.constrained)} in scope, "
        f"{len(unprotected)} unprotected"
    )
    for violation in unprotected:
        lines.append(f"  x {violation.entity_key}  ({violation.subject})  {violation.because}")
    return "\n".join(lines)
