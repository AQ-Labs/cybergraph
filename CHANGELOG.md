# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- OSS launch hardening: security policy, contributor docs, Dependabot, CodeQL,
  OpenSSF Scorecard, SHA-pinned least-privilege workflows, and a gated PyPI
  Trusted Publishing release pipeline.

## [0.1.0]

Initial release: security knowledge-graph build (`build`), multi-language
analyzers (Python, JS/TS, Go, Java, C#, Terraform, Dockerfile), one-command
`analyze` and `quickstart`, scan history with deltas (`history`), interactive
theme-aware HTML report with posture grade and attack-path explorer, scanner
imports (Semgrep/SARIF/Gitleaks/OSV/npm audit), reachability-aware SCA, SARIF
and OpenGraph export, evidence-grounded `ask`/`explain`, and an MCP server.
