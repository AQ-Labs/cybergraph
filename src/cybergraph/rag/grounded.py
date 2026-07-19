"""Evidence-grounded retrieval and answering over the CyberGraph database.

This is the core of CyberGraph's question answering. It retrieves structured
records from the graph (entrypoints, guards, validators, sinks, secrets, attack
paths, findings, vulnerable dependencies), classifies the question, scores
records, and assembles a cited answer with a confidence level. It works with no
LLM at all; when a client is supplied it asks the model to phrase an answer
constrained strictly to the retrieved evidence so it cannot invent findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.remediation import narrative_for_attack_path, remediation_for_rule

# Question categories.
CATEGORY_SINK = "sink_reachability"
CATEGORY_AUTH = "auth_coverage"
CATEGORY_ENTRYPOINT = "entrypoint_exposure"
CATEGORY_SECRET = "secrets"
CATEGORY_DEPENDENCY = "dependencies"
CATEGORY_PR = "pr_changes"
CATEGORY_GENERAL = "general"

# Confidence levels.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_INSUFFICIENT = "insufficient"

_CATEGORY_KEYWORDS: dict[str, set[str]] = {
    CATEGORY_SINK: {
        "sink", "sql", "execute", "query", "shell", "command", "inject", "injection",
        "exec", "eval", "deserialize", "reach", "reaches", "reachable", "dangerous",
    },
    CATEGORY_AUTH: {
        "auth", "authentication", "authenticated", "authorize", "authorization", "login",
        "guard", "guarded", "permission", "role", "protected", "session", "token",
        "unauthenticated",
    },
    CATEGORY_ENTRYPOINT: {
        "route", "routes", "endpoint", "endpoints", "entrypoint", "entrypoints", "exposed",
        "handler", "handlers", "api", "webhook",
    },
    CATEGORY_SECRET: {
        "secret", "secrets", "password", "credential", "credentials", "apikey", "key",
    },
    CATEGORY_DEPENDENCY: {
        "dependency", "dependencies", "package", "packages", "vulnerable", "vulnerability",
        "cve", "osv", "library", "advisory",
    },
    CATEGORY_PR: {"pr", "changed", "change", "changes", "diff", "pull", "request", "delta"},
}


@dataclass(frozen=True)
class Citation:
    file: str = ""
    line: int = 0
    rule: str = ""
    path: tuple[str, ...] = ()

    def render(self) -> str:
        parts: list[str] = []
        if self.file:
            parts.append(f"{self.file}:{self.line}" if self.line else self.file)
        if self.rule:
            parts.append(self.rule)
        if self.path:
            parts.append(" -> ".join(self.path))
        return " | ".join(parts) if parts else "graph"


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    category: str
    title: str
    detail: str
    citation: Citation
    score: float = 0.0


@dataclass(frozen=True)
class GroundedAnswer:
    question: str
    category: str
    confidence: str
    records: tuple[EvidenceRecord, ...]
    answer: str
    used_llm: bool = False
    citations: tuple[str, ...] = field(default_factory=tuple)


def classify_question(question: str) -> str:
    terms = _terms(question)
    best_category = CATEGORY_GENERAL
    best_hits = 0
    for category, keywords in _CATEGORY_KEYWORDS.items():
        hits = sum(1 for term in terms if term in keywords)
        if hits > best_hits:
            best_hits = hits
            best_category = category
    return best_category


def collect_records(repo_root: Path) -> list[EvidenceRecord]:
    """Build every structured evidence record from the stored graph."""
    repo_root = repo_root.resolve()
    store = GraphStore.open_for_repo(repo_root)
    records: list[EvidenceRecord] = []
    try:
        for row in store.conn.execute(
            "SELECT target, file_path, line FROM edges"
            " WHERE kind = 'EXPOSES_ENTRYPOINT' ORDER BY target"
        ):
            records.append(
                EvidenceRecord(
                    "entrypoint", CATEGORY_ENTRYPOINT,
                    f"Entrypoint {_short(row['target'])}",
                    f"Exposed entrypoint `{row['target']}`",
                    Citation(file=row["file_path"], line=row["line"] or 0),
                )
            )
        for row in store.conn.execute(
            "SELECT source, target, file_path, line FROM edges"
            " WHERE kind = 'GUARDS' ORDER BY source"
        ):
            records.append(
                EvidenceRecord(
                    "guard", CATEGORY_AUTH,
                    f"Guard on {_short(row['source'])}",
                    f"`{_short(row['source'])}` is guarded by `{row['target']}`",
                    Citation(file=row["file_path"], line=row["line"] or 0),
                )
            )
        for row in store.conn.execute(
            "SELECT source, target, file_path, line FROM edges"
            " WHERE kind = 'SANITIZES' ORDER BY source"
        ):
            records.append(
                EvidenceRecord(
                    "validator", CATEGORY_SINK,
                    f"Validation in {_short(row['source'])}",
                    f"`{_short(row['source'])}` sanitizes via `{row['target']}`",
                    Citation(file=row["file_path"], line=row["line"] or 0),
                )
            )
        for row in store.conn.execute(
            "SELECT source, target, file_path, line FROM edges"
            " WHERE kind = 'REACHES_SINK' ORDER BY source"
        ):
            records.append(
                EvidenceRecord(
                    "sink", CATEGORY_SINK,
                    f"Sink reached by {_short(row['source'])}",
                    f"`{_short(row['source'])}` reaches sensitive sink `{row['target']}`",
                    Citation(file=row["file_path"], line=row["line"] or 0),
                )
            )
        for row in store.conn.execute(
            "SELECT source, target, file_path, line FROM edges"
            " WHERE kind = 'USES_SECRET' ORDER BY source"
        ):
            records.append(
                EvidenceRecord(
                    "secret", CATEGORY_SECRET,
                    f"Secret used by {_short(row['source'])}",
                    f"`{_short(row['source'])}` uses secret `{row['target']}`",
                    Citation(file=row["file_path"], line=row["line"] or 0),
                )
            )
        for row in store.conn.execute(
            """
            SELECT rule_id, severity, message, file_path, line_start
            FROM findings
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
            """
        ):
            records.append(
                EvidenceRecord(
                    "finding", _finding_category(row["message"], row["rule_id"]),
                    f"{row['severity']} {row['rule_id']}",
                    f"{row['message']} Fix: {remediation_for_rule(row['rule_id'], row['message'])}",
                    Citation(
                        file=row["file_path"], line=row["line_start"] or 0, rule=row["rule_id"]
                    ),
                )
            )
        for row in store.conn.execute(
            """
            SELECT v.name AS vulnerability, d.name AS dependency, e.properties AS properties
            FROM edges e
            JOIN nodes v ON v.key = e.source
            JOIN nodes d ON d.key = e.target
            WHERE e.kind = 'AFFECTS_DEPENDENCY'
            ORDER BY v.name
            """
        ):
            records.append(
                EvidenceRecord(
                    "dependency_vuln", CATEGORY_DEPENDENCY,
                    f"{row['vulnerability']} affects {row['dependency']}",
                    f"Vulnerability `{row['vulnerability']}` "
                    f"affects dependency `{row['dependency']}`",
                    Citation(rule=row["vulnerability"]),
                )
            )
    finally:
        store.close()

    for path in find_attack_paths(repo_root, limit=50):
        records.append(
            EvidenceRecord(
                "attack_path", CATEGORY_SINK,
                f"Attack path {_short(path.entrypoint)} -> {path.sink}",
                narrative_for_attack_path(path),
                Citation(path=tuple(path.nodes)),
            )
        )
    return records


def retrieve_records(repo_root: Path, question: str, limit: int = 8) -> list[EvidenceRecord]:
    category = classify_question(question)
    terms = _terms(question)
    scored: list[EvidenceRecord] = []
    for record in collect_records(repo_root):
        score = 0.0
        if record.category == category:
            score += 2.0
        haystack = f"{record.title} {record.detail} {record.citation.render()}".lower()
        score += sum(1 for term in terms if term in haystack)
        if record.kind in {"attack_path", "finding"}:
            score += 0.5  # always slightly surface concrete risk evidence
        if score > 0:
            scored.append(
                EvidenceRecord(
                    record.kind, record.category, record.title, record.detail,
                    record.citation, score,
                )
            )
    scored.sort(key=lambda r: (-r.score, r.kind, r.title))
    return scored[:limit]


def assess_confidence(category: str, records: list[EvidenceRecord]) -> str:
    if not records:
        return CONFIDENCE_INSUFFICIENT
    in_category = [r for r in records if r.category == category or category == CATEGORY_GENERAL]
    strong = [r for r in in_category if r.kind in {"attack_path", "finding", "dependency_vuln"}]
    if strong and any(r.score >= 2.0 for r in in_category):
        return CONFIDENCE_HIGH
    if in_category:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def answer_grounded(
    repo_root: Path,
    question: str,
    *,
    client=None,
    use_llm: bool = False,
    limit: int = 8,
) -> GroundedAnswer:
    category = classify_question(question)
    records = retrieve_records(repo_root, question, limit=limit)
    confidence = assess_confidence(category, records)
    citations = tuple(r.citation.render() for r in records)

    if confidence == CONFIDENCE_INSUFFICIENT or not records:
        # Never invent an answer when the graph has no supporting evidence.
        return GroundedAnswer(
            question, category, CONFIDENCE_INSUFFICIENT, tuple(records),
            _insufficient_text(question), used_llm=False, citations=citations,
        )

    if use_llm and client is not None:
        answer = _llm_answer(client, question, records, confidence)
        return GroundedAnswer(
            question, category, confidence, tuple(records), answer, True, citations
        )

    return GroundedAnswer(
        question, category, confidence, tuple(records),
        _deterministic_text(question, category, confidence, records), False, citations,
    )


def format_grounded_answer(answer: GroundedAnswer) -> str:
    return answer.answer


# --- internals --------------------------------------------------------------

def _deterministic_text(
    question: str, category: str, confidence: str, records: list[EvidenceRecord]
) -> str:
    lines = [
        f"Question: {question}", f"Category: {category}", f"Confidence: {confidence}",
        "", "Evidence:",
    ]
    for index, record in enumerate(records, start=1):
        lines.append(f"[{index}] {record.title} ({record.citation.render()}) - {record.detail}")
    lines.append("")
    lines.append(_synthesis(category, confidence, records))
    return "\n".join(lines)


def _synthesis(category: str, confidence: str, records: list[EvidenceRecord]) -> str:
    if confidence == CONFIDENCE_LOW:
        # No direct in-category evidence: do not assert category-specific claims.
        return (
            "No direct evidence for this question was found in the graph; the items above are "
            "related context only. Treat this as inconclusive."
        )
    in_category = [r for r in records if r.category == category]
    kinds = {record.kind for record in in_category} if in_category else {r.kind for r in records}
    if category == CATEGORY_SINK:
        if "attack_path" in kinds:
            return (
                "At least one entrypoint reaches a sensitive sink. "
                "Use the cited narrative to verify "
                "the source, missing controls, and recommended fix."
            )
        if "sink" in kinds:
            return (
                "Sensitive sinks are reachable; apply the listed remediation "
                "and confirm inputs are sanitized."
            )
    if category == CATEGORY_AUTH:
        return (
            "Authentication/authorization guards above are the controls "
            "protecting these entrypoints."
        )
    if category == CATEGORY_ENTRYPOINT:
        return (
            "These are the external entrypoints; check each has appropriate "
            "guards and validation."
        )
    if category == CATEGORY_SECRET:
        return "These functions touch secrets; confirm they are not logged or sent to sinks."
    if category == CATEGORY_DEPENDENCY:
        return (
            "These dependencies carry known vulnerabilities; check whether they "
            "are reachable from production code."
        )
    return (
        "Inspect the cited evidence to confirm whether the control or sink is "
        "reachable in the relevant flow."
    )


def _insufficient_text(question: str) -> str:
    return (
        f"Question: {question}\n"
        f"Confidence: {CONFIDENCE_INSUFFICIENT}\n\n"
        "Insufficient evidence in the security graph to answer this question. "
        "Build the graph with `cybergraph build` and import scanner reports, "
        "or ask a more specific "
        "security question (entrypoints, sink reachability, auth coverage, secrets, dependencies)."
    )


def _llm_answer(client, question: str, records: list[EvidenceRecord], confidence: str) -> str:
    evidence_block = "\n".join(
        f"[{index}] ({record.citation.render()}) {record.detail}"
        for index, record in enumerate(records, start=1)
    )
    system = (
        "You are a security code-review assistant. Answer ONLY using the numbered EVIDENCE. "
        "Cite evidence inline as [n] with its file:line. If the evidence does not support a "
        "claim, say the evidence is insufficient. Never invent vulnerabilities, files, functions, "
        "or line numbers that are not in the evidence."
    )
    user = (
        f"QUESTION: {question}\n\n"
        f"EVIDENCE (graph-derived, confidence={confidence}):\n{evidence_block}\n\n"
        "Write a concise, evidence-cited answer."
    )
    text = client.complete(system, user).strip()
    if not text:
        return _deterministic_text(question, classify_question(question), confidence, records)
    return f"{text}\n\nConfidence: {confidence}\nCitations:\n" + "\n".join(
        f"[{index}] {record.citation.render()}" for index, record in enumerate(records, start=1)
    )


def _finding_category(message: str, rule_id: str) -> str:
    text = f"{message} {rule_id}".lower()
    if any(word in text for word in ("sql", "sink", "shell", "exec", "inject", "command")):
        return CATEGORY_SINK
    if any(word in text for word in ("secret", "password", "token", "credential")):
        return CATEGORY_SECRET
    if any(word in text for word in ("auth", "authorization", "permission")):
        return CATEGORY_AUTH
    if any(word in text for word in ("osv", "npm", "cve", "dependency", "vulnerab")):
        return CATEGORY_DEPENDENCY
    return CATEGORY_GENERAL


def _terms(question: str) -> set[str]:
    cleaned = question.lower().replace("?", " ").replace(",", " ").replace(".", " ")
    return {token for token in cleaned.split() if len(token) > 2}


def _short(key: str) -> str:
    return key.rsplit("::", 1)[-1] if key else key
