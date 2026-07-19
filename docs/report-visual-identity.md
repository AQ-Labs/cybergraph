# Report Visual Identity (Spec 3)

Goal: make the HTML report self-explanatory for first-time users and visually
striking, taking cues from popular "code as a graph" visualizations: a dark
canvas with glowing, color-typed nodes, a tiny explained vocabulary
(Node / Edge / Zone), and cluster hulls with plain-English labels.

## Phases

### Phase 1 — Dark theme correctness + neon graph styling

- Migrate all remaining hardcoded light colors (`.path`, toolbar controls,
  `.risk-card`, `.graph-head`, `.pill`, legend text) to the existing CSS
  variables so dark mode has no white patches.
- Theme-aware Cytoscape styling: node label color, text outline, and node
  border read the active theme; styles refresh when the toggle flips.
- Neon look on the dark canvas: brightened group palette, soft glow halos
  (Cytoscape `underlay-*`), dimmed base edges so highlighted paths pop.
- Node size scales with severity so critical risks dominate the eye.

### Phase 2 — "Explained simply" layer

- Replace the flat dot legend with three explainer cards: **Node** (what a
  dot is), **Edge** (what a line is, by style), **Zone** (security layers).
- Guided first view: on load, auto-highlight the #1 attack path and show a
  one-sentence narrative in the details panel instead of an empty prompt.
- Plain-language canvas labels (strip `file::` prefixes; full identifiers
  stay in the details panel).
- A collapsible "How to read this report" intro for first-time readers.

### Phase 3 — Security zones view

- Tag exported nodes with a `zone` (attack surface / guards / logic /
  sensitive sinks / secrets / infrastructure) in `graph_export.py`.
- New "Zones" explorer view using Cytoscape compound parents: dashed hulls
  per zone, laid out left-to-right so the page reads
  entrypoints → guards → sinks like an attack narrative.

### Phase 4 — Declutter

- Group the findings table by rule into expandable cards (one summary row
  per rule with a count, expandable to the individual findings).
- Remove the Top Risks table (duplicated by the clickable risk-strip).
- Severity color accents on the stat tiles (critical red, high amber).
- Subtle motion: fade-in on first layout, pulse on path highlight.

## Non-goals

- No new dependencies; Cytoscape stays vendored and the report offline.
- No changes to analyzers, graph schema, or CLI behavior.
