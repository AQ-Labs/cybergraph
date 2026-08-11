#!/usr/bin/env python3
"""Mutation harness: proof that the test suite can actually fail.

A green test suite proves nothing on its own -- a suite of vacuous assertions is
green against every mutation of the code it claims to guard. This harness turns
the question "can this suite fail when the behaviour breaks?" into a command.

For each mutation in ``MUTATIONS`` it:

1.  restores a pristine clone of ``src/`` (see the editable-install trap below);
2.  runs the mutation's mapped tests against the *clean* clone and requires them
    to PASS -- a test that is red anyway proves nothing when it goes red under a
    mutation;
3.  applies a single, defined source edit to the clone;
4.  re-runs the same mapped tests and requires them to FAIL -- that failure is
    the evidence the suite catches the regression.

A mutation is **CAUGHT** only when step 2 passed and step 4 failed.

The editable-install trap
-------------------------
``cybergraph`` is installed editable via ``_editable_impl_cybergraph.pth`` ->
the real ``src/``. A harness that copies the tree and runs ``pytest`` from the
copy silently imports the *unmutated* original and reports every mutation as
caught-or-uncaught wrongly. So every subprocess here runs with
``PYTHONPATH=<clone>/src`` prepended, and :func:`_assert_clone_is_imported`
confirms ``cybergraph.__file__`` really resolves inside the clone before any
result is trusted.

Scope
-----
Each mutation is scoped to the **narrowest** tests that should catch it, so the
whole run is fast (seconds, not a full-suite pass per mutation). The mapping is
the point: it documents, per disaster class, exactly which test defends which
line. Run ``python benchmark/mutation_harness.py --list`` to see it.

Stdlib + pytest only.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"


@dataclass(frozen=True)
class Mutation:
    """One defined source edit and the tests that must catch it."""

    id: str
    disaster: str  # D1..D8, the disaster class it belongs to
    file: str  # path under src/, e.g. "cybergraph/security/predicates.py"
    old: str
    new: str
    tests: tuple[str, ...]  # pytest node ids, relative to the repo root
    note: str = ""
    count: int = 1  # how many times ``old`` is expected to occur

    def target(self) -> Path:
        return SRC / self.file


# --- The seeded mutation set, grouped by disaster class ----------------------
#
# Every mutation below maps to the disaster class the audit assigned it and to
# the test(s) that now pin it. Adding a mutation here without a test that fails
# under it will make the run report UNCAUGHT -- which is the point.

MUTATIONS: list[Mutation] = [
    # -- D1: a real vulnerability reads `safe` -----------------------------
    Mutation(
        id="D1-cmd-unlocatable-arg-safe",
        disaster="D1",
        file="cybergraph/security/predicates.py",
        old='    command = _find_argument(call, "command")\n'
        "    if command is None:\n"
        "        return VERDICT_UNKNOWN",
        new='    command = _find_argument(call, "command")\n'
        "    if command is None:\n"
        "        return VERDICT_SAFE",
        tests=(
            "tests/test_predicates.py::test_command_path_template_unlocatable_argument_is_unknown",
        ),
        note="an unlocatable command argument must be unknown, never safe",
    ),
    Mutation(
        id="D1-path-unlocatable-arg-safe",
        disaster="D1",
        file="cybergraph/security/predicates.py",
        old='    target = _find_argument(call, "path")\n'
        "    if target is None:\n"
        "        return VERDICT_UNKNOWN",
        new='    target = _find_argument(call, "path")\n'
        "    if target is None:\n"
        "        return VERDICT_SAFE",
        tests=(
            "tests/test_predicates.py::test_command_path_template_unlocatable_argument_is_unknown",
        ),
    ),
    Mutation(
        id="D1-template-unlocatable-arg-safe",
        disaster="D1",
        file="cybergraph/security/predicates.py",
        old='    template = _find_argument(call, "template")\n'
        "    if template is None:\n"
        "        return VERDICT_UNKNOWN",
        new='    template = _find_argument(call, "template")\n'
        "    if template is None:\n"
        "        return VERDICT_SAFE",
        tests=(
            "tests/test_predicates.py::test_command_path_template_unlocatable_argument_is_unknown",
        ),
    ),
    Mutation(
        id="D1-path-origin-carriers-vacuous-truth",
        disaster="D1",
        file="cybergraph/security/predicates.py",
        old="if origin_carriers and all(id(inner) in origin_confined "
        "for inner in origin_carriers):",
        new="if all(id(inner) in origin_confined for inner in origin_carriers):",
        tests=(
            "tests/test_predicates.py::test_a_bare_request_bound_to_a_local_is_not_confined",
            "tests/test_sink_precision.py::test_a_bare_request_bound_to_a_local_reaches_a_path_sink",
        ),
        note="'the whole bug inverted': a bare request bound to a local reads safe",
    ),
    Mutation(
        id="D1-os-system-severity-downgraded",
        disaster="D1",
        file="cybergraph/security/sinks.py",
        old='Sink("os.system", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,',
        new='Sink("os.system", "CG-CMD-EXEC", "CWE-78", SEVERITY_MEDIUM, _CMD,',
        tests=("tests/test_sink_precision.py::test_os_system_command_injection_is_critical",),
        note="nothing asserted the severity of a CG-CMD-EXEC finding",
    ),
    Mutation(
        id="D1-sarif-strips-unverified",
        disaster="D1",
        file="cybergraph/sarif.py",
        old='        "ruleId": row["rule_id"],',
        new='        "ruleId": row["rule_id"].replace("-UNVERIFIED", ""),',
        tests=("tests/test_sarif.py::test_unverified_rule_id_is_preserved_on_export",),
        note="stripping -UNVERIFIED publishes an abstention as a confirmed finding",
    ),
    Mutation(
        id="D1-suppress-inline-window-next-line",
        disaster="D1",
        file="cybergraph/suppressions.py",
        old="    for index in (line_no - 1, line_no - 2):",
        new="    for index in (line_no - 1, line_no - 2, line_no):",
        tests=(
            "tests/test_suppressions.py::test_inline_marker_does_not_suppress_the_next_line",
        ),
    ),
    Mutation(
        id="D1-suppress-config-rule-substring",
        disaster="D1",
        file="cybergraph/suppressions.py",
        old="    return any(rule.lower() in aliases for rule in config.suppressed_rules)",
        new="    return any(\n"
        "        rule.lower() in alias for rule in config.suppressed_rules for alias in aliases\n"
        "    )",
        tests=("tests/test_suppressions.py::test_config_rule_match_is_exact_not_substring",),
    ),
    # -- D6: the command-class scope boundary moving silently ---------------
    Mutation(
        id="D6-flags-double-dash-not-skipped",
        disaster="D6",
        file="cybergraph/security/predicates.py",
        old='if token == "--" or not any(token.startswith(p) for p in runner.flag_prefixes):',
        new="if not any(token.startswith(p) for p in runner.flag_prefixes):",
        tests=("tests/test_predicates.py::test_a_known_runner_with_double_dash_stays_safe",),
    ),
    Mutation(
        id="D6-known-letters-any-not-all",
        disaster="D6",
        file="cybergraph/security/predicates.py",
        old="            and all(letter in runner.known_letters for letter in name[1:])",
        new="            and any(letter in runner.known_letters for letter in name[1:])",
        tests=("tests/test_predicates.py::test_an_unknown_letter_in_a_posix_bundle_abstains",),
        note="an unknown letter in a bundle must not grant safety",
    ),
    # -- D8: taint sources silently lost -----------------------------------
    Mutation(
        id="D8-reads-user-input-drops-source-chain",
        disaster="D8",
        file="cybergraph/analysis/provenance.py",
        old="        if _is_source_chain(child):\n            return True",
        new="        if False and _is_source_chain(child):\n            return True",
        tests=(
            "tests/test_sink_precision.py::test_a_framework_read_bound_to_a_local_still_taints",
        ),
        note="the WSGI/ASGI/Lambda/cgi/factory sources bound to a local",
    ),
    # -- D5 / D1: suppression starving / hiding real output -----------------
    Mutation(
        id="D5-is-suppressed-any-not-all",
        disaster="D5",
        file="cybergraph/security/attack_paths.py",
        old="    return all(any(fnmatch(file, pattern) for pattern in patterns) for file in files)",
        new="    return any(any(fnmatch(file, pattern) for pattern in patterns) for file in files)",
        tests=(
            "tests/test_attack_path_suppressions.py::"
            "test_a_path_crossing_out_of_suppressed_code_is_never_hidden",
        ),
    ),
    Mutation(
        id="D5-no-file-path-is-suppressed",
        disaster="D5",
        file="cybergraph/security/attack_paths.py",
        old="    if not files:\n        return False",
        new="    if not files:\n        return True",
        tests=(
            "tests/test_attack_path_invariants.py::"
            "test_a_path_with_no_identifiable_file_is_never_suppressed",
        ),
    ),
    # -- D1/D5: the five ranked find_attack_paths call sites ---------------
    Mutation(
        id="D1-cli-paths-stops-suppressing",
        disaster="D1",
        file="cybergraph/cli.py",
        old="repo, max_depth=args.max_depth, interprocedural=not args.shallow",
        new="repo, max_depth=args.max_depth, interprocedural=not args.shallow, "
        "apply_suppressions=False",
        tests=(
            "tests/test_attack_path_suppressions.py::test_cli_paths_command_applies_suppressions",
        ),
    ),
    Mutation(
        id="D1-orchestrator-stops-suppressing",
        disaster="D1",
        file="cybergraph/orchestrator.py",
        old="lambda: find_attack_paths(repo_root),",
        new="lambda: find_attack_paths(repo_root, apply_suppressions=False),",
        tests=(
            "tests/test_attack_path_suppressions.py::"
            "test_orchestrator_ranked_paths_apply_suppressions",
        ),
    ),
    Mutation(
        id="D1-review-ranked-stops-suppressing",
        disaster="D1",
        file="cybergraph/security/review.py",
        old="    paths = find_attack_paths(repo_root)\n    changed_set = set(changed_files)",
        new="    paths = find_attack_paths(repo_root, apply_suppressions=False)\n"
        "    changed_set = set(changed_files)",
        tests=(
            "tests/test_review.py::test_ranked_attack_path_count_applies_suppressions",
        ),
    ),
    Mutation(
        id="D1-cloud-stops-suppressing",
        disaster="D1",
        file="cybergraph/security/cloud.py",
        old="    attack_paths = find_attack_paths(repo_root, limit=100)",
        new="    attack_paths = find_attack_paths(repo_root, limit=100, apply_suppressions=False)",
        tests=(
            "tests/test_cloud_code.py::test_cloud_code_paths_apply_suppressions",
        ),
    ),
    Mutation(
        id="D1-strix-stops-suppressing",
        disaster="D1",
        file="cybergraph/security/strix_plan.py",
        old="    paths = find_attack_paths(repo_root, limit=max(limit, 20))",
        new="    paths = find_attack_paths(\n"
        "        repo_root, limit=max(limit, 20), apply_suppressions=False\n"
        "    )",
        tests=(
            "tests/test_strix_plan.py::test_strix_scope_applies_suppressions",
        ),
    ),
    # -- D7: the path-depth bound -------------------------------------------
    Mutation(
        id="D7-max-depth-off-by-one",
        disaster="D7",
        file="cybergraph/security/attack_paths.py",
        old="            if len(path) > max_depth:",
        new="            if len(path) >= max_depth:",
        tests=("tests/test_attack_path_invariants.py::test_the_max_depth_bound_is_inclusive",),
    ),
    # -- D1: attack-path confidence comes from the weakest edge -------------
    Mutation(
        id="D1-confidence-strongest-not-weakest",
        disaster="D1",
        file="cybergraph/security/attack_paths.py",
        old="                        min(conf_rank, _CONF_RANK.get(edge_conf, 1)),",
        new="                        max(conf_rank, _CONF_RANK.get(edge_conf, 1)),",
        tests=(
            "tests/test_attack_path_invariants.py::test_path_confidence_is_the_weakest_edge",
        ),
    ),
    Mutation(
        id="D1-unknown-edge-confidence-high",
        disaster="D1",
        file="cybergraph/security/attack_paths.py",
        old="                        min(conf_rank, _CONF_RANK.get(edge_conf, 1)),",
        new="                        min(conf_rank, _CONF_RANK.get(edge_conf, 3)),",
        tests=(
            "tests/test_attack_path_invariants.py::test_an_unknown_edge_confidence_defaults_to_low",
        ),
    ),
    # -- D2: a live vulnerability reported as fixed / a real change unseen --
    Mutation(
        id="D2-review-worsened-dropped",
        disaster="D2",
        file="cybergraph/security/review.py",
        old='            deltas.append(_with_status(item, "worsened"))',
        new='            deltas.append(_with_status(item, "unchanged"))',
        tests=(
            "tests/test_review.py::test_a_structural_path_becoming_data_reachable_is_worsened",
        ),
    ),
    # -- D1: the tool's own cache dir must be excluded by component, not substring --
    Mutation(
        id="D1-revisions-cybergraph-substring-match",
        disaster="D1",
        file="cybergraph/security/revisions.py",
        old='    return path.split("/", 1)[0] == ".cybergraph"',
        new='    return "cybergraph" in path',
        tests=(
            "tests/test_revisions.py::test_cybergraph_state_dir_is_never_a_changed_file",
        ),
        note="a substring match drops real changed files like `cybergraph_utils.py` "
        "(and every src/cybergraph/*.py change on this tool's own repo) from the "
        "change set -- a fail-open, not the intended `.cybergraph/` exclusion",
    ),
    # -- D2: "I could not look" must never read as "nothing to see" ----------
    Mutation(
        id="D2-revisions-failure-empty-not-flagged",
        disaster="D2",
        file="cybergraph/security/revisions.py",
        old='    ok, _ = _git(repo_root, "rev-parse", "--git-dir")\n'
        "    if not ok:\n"
        '        return Revisions(MODE_WORKTREE, "", "", (), failure="not a git repository")',
        new='    ok, _ = _git(repo_root, "rev-parse", "--git-dir")\n'
        "    if not ok:\n"
        '        return Revisions(MODE_WORKTREE, "", "", ())',
        tests=("tests/test_revisions.py::test_not_a_git_repository_is_a_failure",),
        note="a git failure must produce a failure string, never a silent empty diff",
    ),
    # -- D1: a file that never parsed must not read as clean -----------------
    Mutation(
        id="D1-coverage-failed-as-analyzed",
        disaster="D1",
        file="cybergraph/security/coverage.py",
        old='            results.append(FileCoverage(file, STATUS_FAILED, '
        '"the file could not be read"))',
        new='            results.append(FileCoverage(file, STATUS_ANALYZED, '
        '"the file could not be read"))',
        tests=("tests/test_coverage.py::test_unparseable_file_is_failed_not_clean",),
        note="a parse failure must be `failed`, not `analyzed`",
    ),
    # -- D1: general language blindness must stay represented ----------------
    Mutation(
        id="D1-capability-drops-source-support",
        disaster="D1",
        file="cybergraph/security/capability.py",
        old='    Capability("source_analysis_support",\n'
        '               "Languages CyberGraph can read", SOURCE_GLOBS, True),\n',
        new="",
        tests=("tests/test_capability.py::test_go_change_is_caught_by_general_source_support",),
        note="removing source_analysis_support makes a Go-only change match nothing",
    ),
    # -- D1: an unrecognised policy kind must never vanish silently ----------
    Mutation(
        id="D1-policy-unknown-kind-silently-dropped",
        disaster="D1",
        file="cybergraph/security/policy.py",
        old='    if kind != KIND_REQUIRE_AUTH:\n'
        '        return None, PolicyProblem(rule_id, f"unrecognised rule type `{kind or \'(missing)\'}`")',
        new="    if kind != KIND_REQUIRE_AUTH:\n"
        "        return None, None",
        tests=("tests/test_policy.py::test_unknown_kind_becomes_a_visible_problem",),
        note="an unrecognised rule kind must become a PolicyProblem, never vanish silently",
    ),
    # -- D2: a renamed, unguarded route must still read as protection lost --
    Mutation(
        id="D2-policy-rename-escape-not-detected",
        disaster="D2",
        file="cybergraph/security/policy.py",
        old="    for key in sorted((base_set.constrained & surviving) - current_set.constrained):\n"
        "        before = base_set.entities[key]\n"
        "        after = current_set.entities[key]\n"
        '        kind = "protection_lost" if before.route != after.route else "coverage_shrunk"',
        new="    for key in sorted((base_set.constrained & surviving) - current_set.constrained):\n"
        "        before = base_set.entities[key]\n"
        "        after = current_set.entities[key]\n"
        "        if before.route != after.route:\n"
        "            continue\n"
        '        kind = "coverage_shrunk"',
        tests=(
            "tests/test_policy_delta.py::test_renaming_a_route_out_of_scope_is_caught",
        ),
        note="the C1 rename escape must be flagged as protection_lost, not silently skipped",
    ),
    # -- D2: the verdict layer must never ACCEPT over a review-state check ---
    Mutation(
        id="D2-verdict-review-state-accepts",
        disaster="D2",
        file="cybergraph/security/verdict.py",
        old="    state = STATE_REVIEW if (reasons or triggers_review(checks)) else STATE_ACCEPT",
        new="    state = STATE_ACCEPT",
        tests=(
            "tests/test_verdict.py::test_fail_reviews",
            "tests/test_verdict.py::test_unknown_reviews",
            "tests/test_verdict.py::test_not_supported_reviews_and_is_listed",
        ),
        note="a review-state check (FAIL/UNKNOWN/NOT_SUPPORTED) must never read as accept",
    ),
    Mutation(
        id="D2-revisions-failure-reads-pass",
        disaster="D2",
        file="cybergraph/security/checks.py",
        old="    if revisions_failure:",
        new="    if False and revisions_failure:",
        tests=("tests/test_checks.py::test_git_failure_makes_everything_unknown",),
        note="a revisions failure must force every capability UNKNOWN, "
        "not let evaluation proceed as if nothing failed",
    ),
    # -- D1: a relevant file missing from coverage is silence, not evidence --
    Mutation(
        id="D1-capability-passes-without-evidence",
        disaster="D1",
        file="cybergraph/security/checks.py",
        old="    if missing:\n        return CheckResult(\n            capability_id, UNKNOWN,\n"
        '            f"`{missing[0]}` changed but has no analysis record", len(missing),\n'
        "        )",
        new="    if missing:\n        return CheckResult(\n            capability_id, PASS,\n"
        '            f"`{missing[0]}` changed but has no analysis record", len(missing),\n'
        "        )",
        tests=(
            "tests/test_checks.py::test_relevant_file_missing_from_coverage_is_unknown_not_pass",
        ),
        note="a relevant file absent from coverage entirely is not evidence of safety; "
        "it is silence",
    ),
    # -- D9: a client hook fails open ------------------------------------
    Mutation(
        id="D9-pre-commit-substring-ownership-clobbers-foreign",
        disaster="D9",
        file="cybergraph/hooks/pre_commit.py",
        old="    return any(line.strip().startswith(prefix) for line in content.splitlines())",
        new="    return MARKER in content",
        tests=(
            "tests/test_hooks_pre_commit.py::"
            "test_foreign_hook_mentioning_marker_in_prose_is_still_refused",
        ),
        note="ownership must be a structural line match, not a substring search: a "
        "foreign hook that merely mentions the marker in a comment must still be "
        "refused, not silently claimed and overwritten",
    ),
    Mutation(
        id="D9-staged-falls-back-to-worktree",
        disaster="D9",
        file="cybergraph/security/revisions.py",
        old='    ok, out = _git(repo_root, "diff", "--cached", "--name-only")',
        new='    ok, out = _git(repo_root, "diff", "--name-only", "HEAD")',
        tests=(
            "tests/test_revisions_staged.py::"
            "test_staged_mode_ignores_unstaged_edit_to_tracked_file",
        ),
        note="staged mode must read the index (--cached), not the working tree",
    ),
    # -- D9: config posture findings must reach the verdict, not be dropped --
    Mutation(
        id="D9-config-posture-finding-ignored",
        disaster="D9",
        file="cybergraph/security/checks.py",
        old="    confirmed = [f for f in findings if f.rule_id in rules]",
        new="    confirmed = []",
        tests=(
            "tests/test_config_posture_capability.py::test_disabling_rls_makes_check_review",
        ),
        note="a config posture finding must FAIL the capability, not be dropped",
    ),
    Mutation(
        id="D9-unparsed-config-reads-clean",
        disaster="D9",
        file="cybergraph/analysis/bucket_policy.py",
        old="    data = json.loads(source)  # JSONDecodeError propagates -> registry containment",
        new="    try:\n        data = json.loads(source)\n"
        "    except ValueError:\n        return nodes, [], findings",
        tests=(
            "tests/test_config_posture_capability.py::"
            "test_malformed_bucket_policy_reads_unknown",
        ),
        note="an unparseable config must read UNKNOWN, never a clean pass",
    ),
    # -- D9: CORS/client-secret detectors fail open ------------------------
    Mutation(
        id="D9-cors-credentialed-wildcard-missed",
        disaster="D9",
        file="cybergraph/analysis/python.py",
        old='        if not _kw_is_true(kw.get("allow_credentials")):\n'
        "            continue",
        new="        if True:\n            continue",
        tests=("tests/test_python_cors.py::test_credentialed_wildcard_is_flagged",),
        note="a credentialed-wildcard CORS must be flagged, never dropped",
    ),
    Mutation(
        id="D9-client-secret-exposure-missed",
        disaster="D9",
        file="cybergraph/analysis/javascript.py",
        old='_NEXT_PUBLIC_RE = re.compile(r"NEXT_PUBLIC_[A-Za-z0-9_]+")',
        new='_NEXT_PUBLIC_RE = re.compile(r"__CYBERGRAPH_NEVER_MATCHES__")',
        tests=("tests/test_js_cors_nextjs.py::test_next_public_secret_is_flagged",),
        note="a NEXT_PUBLIC_ secret must be flagged, never missed",
    ),
    # -- D9: the JS verdict assessor must never fail open --------------------
    Mutation(
        id="D9-js-tainted-sqli-reads-safe",
        disaster="D9",
        file="cybergraph/analysis/js_provenance.py",
        old="        if any(n in tainted_names for n in names):\n"
        "            return VERDICT_UNSAFE",
        new="        if any(n in tainted_names for n in names):\n"
        "            return VERDICT_SAFE",
        tests=("tests/test_js_provenance.py::test_assess_sql_tainted_variable_is_unsafe",),
        note="a tainted JS sink argument must not read safe",
    ),
    Mutation(
        id="D9-js-unresolved-var-reads-safe",
        disaster="D9",
        file="cybergraph/analysis/js_provenance.py",
        old="        if names or unresolved:\n"
        "            # a candidate variable (resolved or not) or an operand we could not\n"
        "            # prove literal -> never read as safe\n"
        "            return VERDICT_UNKNOWN",
        new="        if names or unresolved:\n"
        "            # a candidate variable (resolved or not) or an operand we could not\n"
        "            # prove literal -> never read as safe\n"
        "            return VERDICT_SAFE",
        tests=(
            "tests/test_js_provenance.py::test_assess_sql_unresolved_variable_is_unknown_not_safe",
        ),
        note="a JS variable CyberGraph cannot resolve must read UNKNOWN, never SAFE",
    ),
    Mutation(
        id="D9-js-concat-operand-reads-safe",
        disaster="D9",
        file="cybergraph/analysis/js_provenance.py",
        old="        idents = _IDENT_RE.findall(p)\n"
        "        if not idents:\n"
        "            unresolved = True\n"
        "            continue",
        new="        m = _IDENT_RE.match(p)\n"
        "        if m is None:\n"
        "            continue\n"
        "        idents = [m.group(0)]",
        tests=("tests/test_js_provenance.py::test_assess_paren_tainted_operand_is_unsafe",),
        note="a '+' operand not led by an identifier character (e.g. `(id)`, `[id]`, "
        "`(id || 1)`) must still have its identifiers found; matching only from the "
        "operand's start silently drops the name and the construction reads safe",
    ),
]


def _clone_src() -> Path:
    """A pristine copy of ``src/`` in a temp dir; returns the clone's src root."""
    tmp = Path(tempfile.mkdtemp(prefix="cybergraph-mutation-"))
    clone_src = tmp / "src"
    shutil.copytree(SRC, clone_src)
    return clone_src


def _env_for(clone_src: Path) -> dict[str, str]:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(clone_src) + (os.pathsep + existing if existing else "")
    return env


def _assert_clone_is_imported(clone_src: Path) -> None:
    """Fail loudly if the editable install shadows the clone (the harness trap)."""
    proc = subprocess.run(
        [sys.executable, "-c", "import cybergraph, sys; sys.stdout.write(cybergraph.__file__)"],
        env=_env_for(clone_src),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    imported = Path(proc.stdout.strip())
    if clone_src not in imported.parents:
        raise SystemExit(
            "harness trap: `import cybergraph` resolved to "
            f"{imported}\nnot inside the clone {clone_src}. "
            "PYTHONPATH is not shadowing the editable install; results are meaningless."
        )


def _restore(clone_src: Path, mutation: Mutation) -> None:
    shutil.copy2(mutation.target(), clone_src / mutation.file)


def _apply(clone_src: Path, mutation: Mutation) -> None:
    target = clone_src / mutation.file
    text = target.read_text(encoding="utf-8")
    occurrences = text.count(mutation.old)
    if occurrences != mutation.count:
        raise SystemExit(
            f"[{mutation.id}] expected {mutation.count} occurrence(s) of the mutated "
            f"snippet in {mutation.file}, found {occurrences}. The source moved; "
            "update the mutation."
        )
    target.write_text(text.replace(mutation.old, mutation.new), encoding="utf-8")


def _run_tests(clone_src: Path, tests: tuple[str, ...]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests],
        env=_env_for(clone_src),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


@dataclass
class Result:
    mutation: Mutation
    baseline_green: bool
    caught: bool
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.baseline_green and self.caught


def run(selected: list[Mutation]) -> list[Result]:
    clone_src = _clone_src()
    _assert_clone_is_imported(clone_src)
    baseline_cache: dict[tuple[str, ...], bool] = {}
    results: list[Result] = []
    try:
        for mutation in selected:
            _restore(clone_src, mutation)
            key = mutation.tests
            if key not in baseline_cache:
                baseline_cache[key] = _run_tests(clone_src, key).returncode == 0
            baseline_green = baseline_cache[key]

            _apply(clone_src, mutation)
            proc = _run_tests(clone_src, mutation.tests)
            _restore(clone_src, mutation)

            caught = proc.returncode != 0
            detail = ""
            if not baseline_green:
                detail = "mapped tests are NOT green on the clean clone"
            elif not caught:
                detail = "mutation applied, tests still PASS -> suite is blind"
            results.append(Result(mutation, baseline_green, caught, detail))
    finally:
        shutil.rmtree(clone_src.parent, ignore_errors=True)
    return results


def _print_list() -> None:
    width = max(len(m.id) for m in MUTATIONS)
    print(f"{'MUTATION':<{width}}  CLASS  TESTS")
    for mutation in MUTATIONS:
        tests = "\n".join(f"{'':<{width}}         - {t}" for t in mutation.tests)
        print(f"{mutation.id:<{width}}  {mutation.disaster:<5}  {mutation.file}")
        print(tests)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list mutations and their tests")
    parser.add_argument(
        "--id", action="append", default=[], help="run only the mutation(s) with these id(s)"
    )
    parser.add_argument(
        "--disaster", action="append", default=[], help="run only mutations in these classes"
    )
    args = parser.parse_args(argv)

    if args.list:
        _print_list()
        return 0

    selected = MUTATIONS
    if args.id:
        selected = [m for m in selected if m.id in set(args.id)]
    if args.disaster:
        selected = [m for m in selected if m.disaster in set(args.disaster)]
    if not selected:
        print("no mutations selected")
        return 2

    results = run(selected)
    width = max(len(r.mutation.id) for r in results)
    print(f"\n{'MUTATION':<{width}}  CLASS  RESULT")
    for r in results:
        status = "CAUGHT" if r.ok else "UNCAUGHT"
        line = f"{r.mutation.id:<{width}}  {r.mutation.disaster:<5}  {status}"
        if r.detail:
            line += f"  ({r.detail})"
        print(line)

    uncaught = [r for r in results if not r.ok]
    print(f"\n{len(results) - len(uncaught)}/{len(results)} mutations caught.")
    if uncaught:
        print("UNCAUGHT mutations mean the suite cannot fail when that behaviour breaks.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
