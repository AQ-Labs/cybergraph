# Evidence-availability ablation

Run from the repository root with Python 3.10 or newer:

```sh
python benchmark/run_retrieval_ablation.py
```

No model, API key, application installation, or network request is required.
The runner rebuilds the existing positive fixture graphs and writes
`protocol.json` and `results.json` here. All questions, returned records,
citations, ranking scores, context lengths, and the retriever source checksum
are preserved. The two negative fixtures remain part of the separate
reachability regression check; they have no target endpoint pair for this
comparison.

## Protocol and Results

For each of the nine existing positive paths, ask:
"What sensitive sink is reachable from [entrypoint]?"

Use the same category/lexical ranking as `rag/grounded.py` with three record
pools. Return at most two complete records and 2,000 characters. Oversized
records are skipped, not truncated. This is a shared cap, not matched actual
context length.

| Evidence pool | Both endpoint labels present | Connected path citation | Mean characters |
| --- | --- | --- | --- |
| Findings only | 0/9 | 0/9 | 136.3 |
| Records without paths | 8/9 | 0/9 | 243.2 |
| Records with paths | 9/9 | 9/9 | 543.7 |

These are seeded, template-generated questions, not an independent held-out
retrieval benchmark. Case-insensitive substring label matching may admit
incidental matches and does not validate relationship correctness. The longer
path contexts are a confound. Explicit path citations are structurally absent
when path records are removed; the secondary metric measures availability,
not superior correctness.

This does not measure exploitability, LLM faithfulness, developer productivity,
or real-world vulnerability detection. No question-specific tuning or model
generation was used. The protocol was implemented before the first run but
was not externally preregistered.
