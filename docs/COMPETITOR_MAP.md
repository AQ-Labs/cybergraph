# CyberGraph — Competitive & Capability Map (Phase 0)

Positioning input for the graph-grounded, developer-first security tool. Sourced from a 2026-06
deep-research sweep (20 adversarially-verified findings). Treat vendor figures as directional, not
benchmarks.

## The bet (what the research supports)
Lead with **reachability-grounded SAST + LLM false-positive triage**. Top-venue work validates the
CPG+LLM pairing CyberGraph already has, and the dominant developer pain is **SAST false positives /
alert fatigue**.
- LLMxCPG (USENIX Security '25): CPG-guided slicing feeds the LLM only the vuln-relevant subgraph
  (67–91% code reduction), +15–40% F1 over baselines.
- IRIS (ICLR '25): LLM-inferred taint specs + static analysis beat CodeQL by +28 vulns at lower
  false-discovery rate.
- LLM4PFA / "Sifting the Noise" (2025–26 preprints): LLM agents grounded in program facts remove
  72–96% of static-analysis false positives while preserving recall (recall guardrails required).
- AdaTaint (architectural principle): ground LLM suggestions in program facts + constraint
  validation, never the LLM alone — exactly CyberGraph's cited/confidence/abstain design.

## Landscape (capabilities, gaps)
| Tool | What it does | Gap CyberGraph can exploit |
|---|---|---|
| **CodeQL** | Query-based dataflow/taint SAST; strong, deep | Steep query authoring; flat findings; high noise; no LLM triage |
| **Semgrep** | Fast pattern/lightweight dataflow rules | Pattern-bound; FP noise; limited cross-file reachability |
| **Joern** | Open code property graph engine | Engine, not a dev-facing, cited, LLM-grounded product |
| **Snyk Code** | Commercial SAST + SCA, IDE/PR | Closed; reachability limited; per-seat cost |
| **Endor Labs** | Reachability-based SCA, multi-factor prioritization (~92% noise cut, vendor-reported) | Dependencies only; commercial/cloud |
| **Socket (+Coana)** | Reachability SCA + malicious-package detection | Supply-chain only; commercial |
| **BloodHound CE / ForceHound** | Identity/infra attack-path graphs; OpenGraph schema | Infra/identity, not code-level; CyberGraph can emit OpenGraph |
| **Wiz / Orca** | Cloud security graph (CSPM/CNAPP) | Cloud posture, not in-repo dev-loop SAST |
| **graphify / gitnexus** | Code knowledge graphs for navigation/RAG | Not security-typed; no reachability/attack paths |

## The gap CyberGraph can own
A **free, local-first, developer-first** security tool that is **graph-grounded + LLM-triaged** with
**cited, confidence-scored, reachability-constrained** findings and an **abstain guard** — spanning
**code reachability (now) → reachable-dependency CVEs (next) → cloud/identity attack paths (later)** —
delivered first as a Claude Code skill at IDE/PR time.

## Sequencing
1. **Phase 1 (wedge):** reachability-grounded SAST + LLM FP-triage (highest evidence, dominant pain).
2. **Phase 2:** reachability-based SCA (reachable CVEs only; multi-factor prioritization).
3. **Phase 3:** cloud/identity/IaC attack paths; optional BloodHound OpenGraph export.

## Open positioning questions
- Do 72–96% FP-reduction results hold on real multi-language PRs, and at what recall cost? (Phase 0
  benchmark + recall guardrail exist to answer this.)
- OpenGraph interop vs native schema for adoption.

_Caveat: deep-research coverage of Semgrep/Socket/Snyk/Wiz/graphify/gitnexus specifics was partial;
refine entries above with hands-on evaluation before external claims._
