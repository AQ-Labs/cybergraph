# CyberGraph Architecture

CyberGraph is built around one idea: security review should be graph-first, not report-first.

## Pipeline

1. Collect source files from a repository.
2. Parse code into graph nodes and edges.
3. Detect security controls, sensitive sinks, entrypoints, and lightweight findings.
4. Import external scanner reports into the same database.
5. Retrieve evidence for security questions using graph context plus findings.
6. One 'analyze' command builds once and fans every analysis into a shared AnalysisResult consumed by the CLI, HTML report, and MCP server.
7. Every build/scan/analyze records a line-stable snapshot of findings; 'history' reports new/fixed/regressed since the previous scan (history tables survive rebuilds).

## Current graph model

- `nodes`: files and code symbols.
- `edges`: calls, entrypoints, sink reachability, and security relationships.
- `findings`: scanner or built-in analyzer findings with file/line evidence.

## Near-term roadmap

- Add JavaScript/TypeScript route and sink analyzers.
- Add dependency manifest ingestion for `package-lock.json`, `requirements.txt`, and `pyproject.toml`.
- Add richer source-to-sink traversal with guard/sanitizer awareness.
- Add HTML visualization for security layers and attack paths.
- Add MCP review tools for PR security deltas.
