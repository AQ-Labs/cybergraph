"""The single orchestrator behind every `check` surface.

The CLI and the MCP tool both call :func:`check_change` and neither imports the
other. Two presentation surfaces coupled through a private function is how they
drift.

Two failure rules:

*A base that cannot be read is UNKNOWN, not an empty policy.* Returning an empty
policy is indistinguishable from "the base had no policy," which silently
disables tamper detection at exactly the moment git is broken.

*The base analysis is cached by commit sha.* Materialising and analyzing the
whole base tree on every invocation is O(repo), not O(diff), and this runs at
the moment a developer is waiting to accept a diff.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from cybergraph import __version__
from cybergraph.build import build_graph
from cybergraph.config import CyberGraphConfig, load_config
from cybergraph.security.capability import CAPABILITIES, FAIL
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import assess_coverage
from cybergraph.security.policy import (
    Policy,
    PolicyChange,
    ProtectedSet,
    diff_configs,
    diff_policies,
    evaluate_policy,
    load_policy,
)
from cybergraph.security.review import _materialize_git_ref, review_security_delta
from cybergraph.security.revisions import resolve_revisions
from cybergraph.security.verdict import (
    Provenance,
    Verdict,
    decide,
    load_changed_findings,
)

BASE_CACHE_DIR = "base"
#: Written last, after a base ``build_graph`` returns. Its presence is the only
#: proof the build *finished*: ``GraphStore.open_for_repo`` creates ``graph.db``
#: at the *start* of a build, so a db alone can be a partial tree left by an
#: interrupted process. Reusing such a partial base under-reports its protections
#: and can hide a policy weakening -- a wrong ACCEPT on the tamper dimension.
BASE_COMPLETE_MARKER = ".complete"

#: Policy-diff kinds that describe a route lacking its login check. The
#: ``declared_login_rules`` capability reports the *same* event as a FAIL, so
#: passing both to ``decide`` double-reports one guard loss. When that check
#: fails, these are dropped and the capability check is the single source.
_GUARD_LOSS_KINDS = frozenset({"promise_broken", "promise_unmet"})


@dataclass(frozen=True)
class BaseState:
    policy: Policy
    protected: ProtectedSet
    config: CyberGraphConfig
    failure: str = ""


def check_change(
    repo_root: Path, base: str | None = None, mode: str | None = None
) -> Verdict:
    """Decide whether the current change preserves this project's guarantees."""
    repo = Path(repo_root).resolve()
    revisions = resolve_revisions(repo, base=base, mode=mode)

    build_graph(repo)
    policy = load_policy(repo)
    current = evaluate_policy(repo, policy)

    base_state = _base_state(repo, revisions.base_ref) if not revisions.failure else None
    failure = revisions.failure or (base_state.failure if base_state else "")

    changes: list[PolicyChange] = []
    if base_state is not None and not base_state.failure:
        changes.extend(diff_policies(base_state.policy, base_state.protected, policy, current))
        changes.extend(diff_configs(base_state.config, load_config(repo)))

    findings = load_changed_findings(repo, revisions.changed_files)
    risk_deltas = list(_risk_deltas(repo, revisions.base_ref, failure))
    checks = evaluate_capabilities(
        changed_files=revisions.changed_files,
        findings=findings,
        coverage=assess_coverage(repo, revisions.changed_files),
        protected_set=current,
        policy=policy,
        risk_deltas=risk_deltas,
        revisions_failure=failure,
    )

    return decide(
        checks,
        _dedupe_guard_reasons(changes, checks),
        Provenance(
            tool_version=__version__,
            base_ref=revisions.base_ref,
            head_ref=revisions.head_ref or "worktree",
            mode=revisions.mode,
            policy_hash=policy.source_hash,
            capabilities=tuple(c.id for c in CAPABILITIES if c.supported),
        ),
        findings=findings,
        protected_set=current,
        changed_files=revisions.changed_files,
        risk_deltas=risk_deltas,
    )


def _dedupe_guard_reasons(
    changes: list[PolicyChange], checks: list
) -> list[PolicyChange]:
    """Drop guard-loss policy changes the ``declared_login_rules`` FAIL already owns.

    Both the capability check and ``promise_broken``/``promise_unmet`` are
    derived from the same ``ProtectedSet.unprotected``; the policy changes are a
    subset of what the FAIL covers, so removing them when the check fails reports
    each guard loss exactly once instead of twice. When the check is UNKNOWN (a
    policy problem, no policy declared) the two describe *different* events -- "we
    could not check" versus "this route lost its guard" -- so nothing is dropped.
    """
    login_failed = any(
        c.capability_id == "declared_login_rules" and c.status == FAIL for c in checks
    )
    if not login_failed:
        return changes
    return [change for change in changes if change.kind not in _GUARD_LOSS_KINDS]


def _risk_deltas(repo: Path, base_ref: str, failure: str):
    if failure or not base_ref:
        return ()
    try:
        return review_security_delta(repo, base=base_ref).risk_deltas
    except Exception:  # a git or analysis error must not read as "no new risk"
        return ()


def _base_state(repo: Path, base_ref: str) -> BaseState:
    """Load the base revision's policy, protected set and config.

    Cached under ``.cybergraph/base/<sha>`` so the base tree is materialised and
    analyzed once per base commit rather than once per check.
    """
    if not base_ref:
        return BaseState(Policy(), ProtectedSet(), CyberGraphConfig())

    sha = _resolve_sha(repo, base_ref)
    if not sha:
        return BaseState(
            Policy(), ProtectedSet(), CyberGraphConfig(),
            failure=f"could not resolve the base revision `{base_ref}`",
        )

    cache_root = repo / ".cybergraph" / BASE_CACHE_DIR
    cached = cache_root / sha
    if not (cached / BASE_COMPLETE_MARKER).exists():
        # No completion marker means the cache is absent or was left partial by
        # an interrupted build; either way it must not be trusted. Discard any
        # partial tree and rebuild from scratch.
        _prune(cache_root, keep=sha)
        shutil.rmtree(cached, ignore_errors=True)
        cached.mkdir(parents=True, exist_ok=True)
        if not _materialize_git_ref(repo, sha, cached):
            shutil.rmtree(cached, ignore_errors=True)
            return BaseState(
                Policy(), ProtectedSet(), CyberGraphConfig(),
                failure=f"could not read the base revision `{base_ref}`",
            )
        build_graph(cached)
        # Written last: its presence is the promise that the build finished.
        (cached / BASE_COMPLETE_MARKER).write_text("", encoding="utf-8")

    base_policy = load_policy(cached)
    return BaseState(base_policy, evaluate_policy(cached, base_policy), load_config(cached))


def _resolve_sha(repo: Path, ref: str) -> str:
    from cybergraph.security.revisions import _git

    ok, output = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return output.strip() if ok else ""


def _prune(cache_root: Path, keep: str) -> None:
    """Keep one base analysis; the previous one is dead as soon as the base moves."""
    if not cache_root.exists():
        return
    for entry in cache_root.iterdir():
        if entry.name != keep:
            shutil.rmtree(entry, ignore_errors=True)
