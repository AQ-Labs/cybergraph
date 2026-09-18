"""Frozen, descriptive retrieval ablation; not a vulnerability accuracy benchmark."""

import hashlib
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cybergraph.build import build_graph  # noqa: E402
from cybergraph.rag.grounded import _terms, classify_question, collect_records  # noqa: E402

PROTOCOL = {
    "question_template": "What sensitive sink is reachable from {entrypoint}?",
    "cases": (
        "All expected positive paths in the existing 11-case seeded corpus; "
        "negative cases have no target pair and are excluded."
    ),
    "limit_records": 2,
    "limit_characters": 2000,
    "ranking": (
        "Unchanged category, lexical-overlap, and kind bonus from grounded.py; "
        "ties by kind then title."
    ),
    "conditions": ["findings_only", "without_path_records", "with_path_records"],
    "metric": (
        "Both expected endpoint and sink label occur in returned evidence, "
        "case-insensitive substring matching as in the corpus. "
        "This does not validate their relationship."
    ),
    "secondary_metric": (
        "A single returned path citation contains both labels. "
        "This directly measures path availability, not independent correctness."
    ),
    "scope": (
        "Descriptive ablation on seeded examples, not held-out retrieval evaluation, "
        "LLM evaluation, or comparison against another tool."
    ),
}


def render(record):
    return f"{record.title}\n{record.detail}\n{record.citation.render()}"


def retrieve(records, question):
    category, terms = classify_question(question), _terms(question)
    ranked = []
    for r in records:
        haystack = f"{r.title} {r.detail} {r.citation.render()}".lower()
        score = 2.0 * (r.category == category) + sum(t in haystack for t in terms)
        score += 0.5 * (r.kind in {"finding", "attack_path"})
        if score > 0:
            ranked.append(replace(r, score=score))
    ranked.sort(key=lambda r: (-r.score, r.kind, r.title))
    selected, used = [], 0
    for r in ranked:
        size = len(render(r)) + (2 if selected else 0)
        if used + size > PROTOCOL["limit_characters"]:
            continue
        selected.append(r)
        used += size
        if len(selected) == PROTOCOL["limit_records"]:
            break
    return selected, used


def main():
    out = ROOT / "benchmark/retrieval"
    out.mkdir(exist_ok=True)
    (out / "protocol.json").write_text(json.dumps(PROTOCOL, indent=2) + "\n")
    rows = []
    for file in sorted((ROOT / "benchmark/cases").glob("*/expected.json")):
        expected = json.loads(file.read_text())
        if not expected.get("expected_paths"):
            continue
        build_graph(file.parent)
        records = collect_records(file.parent)
        for pair in expected["expected_paths"]:
            question = PROTOCOL["question_template"].format(**pair)
            entry, sink = pair["entrypoint"].lower(), pair["sink"].lower()
            for condition in PROTOCOL["conditions"]:
                pool = [
                    r
                    for r in records
                    if condition == "with_path_records"
                    or (condition == "without_path_records" and r.kind != "attack_path")
                    or (condition == "findings_only" and r.kind == "finding")
                ]
                selected, chars = retrieve(pool, question)
                text = "\n\n".join(map(render, selected)).lower()
                chain = any(
                    entry in " ".join(r.citation.path).lower()
                    and sink in " ".join(r.citation.path).lower()
                    for r in selected
                )
                rows.append(
                    {
                        "case": file.parent.name,
                        "question": question,
                        "expected": pair,
                        "condition": condition,
                        "endpoint_pair_present": entry in text and sink in text,
                        "path_citation_present": chain,
                        "characters": chars,
                        "records": [asdict(r) for r in selected],
                    }
                )
    summary = {}
    for condition in PROTOCOL["conditions"]:
        subset = [r for r in rows if r["condition"] == condition]
        summary[condition] = {
            "questions": len(subset),
            "endpoint_pairs": sum(r["endpoint_pair_present"] for r in subset),
            "path_citations": sum(r["path_citation_present"] for r in subset),
            "mean_characters": round(sum(r["characters"] for r in subset) / len(subset), 1),
        }
    result = {
        "protocol": PROTOCOL,
        "grounded_py_sha256": hashlib.sha256(
            (ROOT / "src/cybergraph/rag/grounded.py").read_bytes()
        ).hexdigest(),
        "summary": summary,
        "rows": rows,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
