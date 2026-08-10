"""What CyberGraph claims to check, and what it admits it cannot.

Five states. The distinctions between the last three carry the product's
credibility:

``PASS``            the check ran on this change and found nothing
``FAIL``            the check ran and found something
``NOT_APPLICABLE``  supported, but nothing in this change is in its scope
``UNKNOWN``         supported, but it could not run here
``NOT_SUPPORTED``   the capability does not exist yet

``NOT_APPLICABLE`` and ``NOT_SUPPORTED`` look alike and are not. A README-only
change is NOT_APPLICABLE everywhere and can honestly accept. A change to a
language with no analyzer is NOT_SUPPORTED and cannot -- accepting there is false
assurance, which for a verification tool is worse than a false positive.

Coverage is *declared*, never inferred: a capability states the file globs it
claims. Asking a non-existent analyzer whether it would have found something is
circular. ``source_analysis_support`` exists so that general language blindness
is represented directly, rather than being implied by whichever future
capability happens to list an extension.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
NOT_SUPPORTED = "not_supported"

_REVIEW_STATES = frozenset({FAIL, UNKNOWN, NOT_SUPPORTED})

PYTHON_GLOBS = ("*.py",)
WEB_GLOBS = ("*.ts", "*.tsx", "*.js", "*.jsx", "*.vue", "*.svelte", "*.mjs", "*.cjs")

# Every extension CyberGraph recognises as executable source, supported or not.
SOURCE_GLOBS = (
    *PYTHON_GLOBS, *WEB_GLOBS,
    "*.go", "*.java", "*.cs", "*.rb", "*.php", "*.rs", "*.kt", "*.swift",
    "*.scala", "*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.sh", "*.bash",
)
# The subset with a Phase 1 analyzer that produces findings.
VERIFIED_GLOBS = PYTHON_GLOBS

# Declarative config surfaces with a Phase-2 posture analyzer. Kept narrow so a
# changed config file that is analyzed-and-clean can PASS and an unparsed one
# reads UNKNOWN -- broad globs (e.g. every *.yaml) would make unrelated changes
# review. Single source of truth for the capability's `covers` and coverage.
CONFIG_GLOBS = (
    "*.tf",
    "*.rules", "firebase.json", "*/firebase.json",
    "supabase/*.sql", "*/supabase/*.sql",
    "*bucket-policy*.json", "*bucket_policy*.json", "*.iam.json",
)


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    covers: tuple[str, ...]
    supported: bool


CAPABILITIES: tuple[Capability, ...] = (
    Capability("sql_construction", "Unsafe database queries", PYTHON_GLOBS, True),
    Capability("command_execution", "Unsafe system commands", PYTHON_GLOBS, True),
    Capability("code_execution", "Code run from user input", PYTHON_GLOBS, True),
    Capability("deserialization", "Unsafe data loading", PYTHON_GLOBS, True),
    Capability("path_access", "Files opened from user input", PYTHON_GLOBS, True),
    Capability("declared_login_rules", "Your declared login rules", PYTHON_GLOBS, True),
    Capability("reachable_data_paths",
               "New routes from the internet to sensitive code", PYTHON_GLOBS, True),
    Capability("source_analysis_support",
               "Languages CyberGraph can read", SOURCE_GLOBS, True),
    Capability("client_secret_boundary", "Secrets reaching the browser", WEB_GLOBS, False),
    Capability("cloud_configuration",
               "Cloud and database configuration", CONFIG_GLOBS, True),
)

_BY_ID = {capability.id: capability for capability in CAPABILITIES}


@dataclass(frozen=True)
class CheckResult:
    capability_id: str
    status: str
    detail: str = ""
    evidence_count: int = 0


def relevance(changed_files: tuple[str, ...]) -> dict[str, bool]:
    """Which capabilities this change falls within the declared scope of."""
    return {
        capability.id: any(
            fnmatch(file, pattern)
            for file in changed_files
            for pattern in capability.covers
        )
        for capability in CAPABILITIES
    }


def unverified_source_files(changed_files: tuple[str, ...]) -> tuple[str, ...]:
    """Changed source files in a language with no Phase 1 analyzer."""
    return tuple(
        file
        for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
        and not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS)
    )


def label_for(capability_id: str) -> str:
    capability = _BY_ID.get(capability_id)
    return capability.label if capability else capability_id


def triggers_review(results: list[CheckResult]) -> bool:
    """Any failure, blind spot, or unsupported-but-relevant check forces review."""
    return any(result.status in _REVIEW_STATES for result in results)
