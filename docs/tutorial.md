# Five-Minute Tutorial

This walkthrough takes you from install to an interactive security graph and a
cited answer in about five minutes. It uses the shipped demo apps, so it needs
no setup beyond installing CyberGraph.

## 1. Install

```bash
python -m pip install -e ".[dev]"
# Optional extras:
#   ".[mcp]"  -> MCP server for AI assistants
#   ".[llm]"  -> Anthropic / OpenAI / Kimi providers for grounded phrasing
```

## 2. Build a security graph

```bash
cybergraph build examples/vulnerable-fastapi
```

This writes a local graph to `examples/vulnerable-fastapi/.cybergraph/graph.db`.
Nothing leaves your machine.

## 3. Ask a grounded question

```bash
cybergraph explain "Which routes reach SQL execution?" --repo examples/vulnerable-fastapi
```

Every factual line is backed by a citation (`file:line`, rule id, or a graph
path) and the answer carries a confidence level. If the graph has no supporting
evidence, the answer says so instead of guessing.

## 4. See interprocedural reachability across files and languages

```bash
cybergraph paths --repo examples/vulnerable-go
cybergraph paths --repo examples/vulnerable-go --shallow   # contrast: no cross-function traversal
```

The default run reports `route:/users -> listUsers -> db.Query` with a
confidence; `--shallow` shows what a non-interprocedural tool would miss.

## 5. Open the interactive explorer

```bash
cybergraph visualize examples/vulnerable-fastapi --output report.html
```

Open `report.html` in any browser (no network needed). You can:

- search nodes and filter by security layer or severity,
- click a node to inspect its location, findings, properties, and neighbours,
- pick an entrypoint to highlight its path to a sensitive sink.

## 6. (Optional) Let an LLM phrase the answer, grounded in evidence

CyberGraph is local-only by default. To opt into LLM phrasing, configure a
provider and pass `--llm`:

```bash
# Kimi 2.6 (Moonshot, OpenAI-compatible)
export CYBERGRAPH_LLM_PROVIDER=kimi
export MOONSHOT_API_KEY=sk-...
# or: CYBERGRAPH_LLM_PROVIDER=anthropic + ANTHROPIC_API_KEY
# or: CYBERGRAPH_LLM_PROVIDER=openai    + OPENAI_API_KEY

cybergraph explain "Which routes reach SQL execution?" --repo examples/vulnerable-fastapi --llm
```

The model only ever sees graph-derived evidence, is instructed to cite it, and
is not called at all when the evidence is insufficient — so it cannot invent
vulnerabilities.

## Where to go next

- [Architecture](architecture.md)
- [Security ontology](security-ontology.md)
- Demo apps: `examples/vulnerable-fastapi`, `examples/vulnerable-go`, `examples/vulnerable-express`
