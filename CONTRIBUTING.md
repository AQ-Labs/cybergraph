# Contributing to CyberGraph

Thanks for your interest! This guide covers everything needed to land a change.

## Dev setup

```bash
python -m pip install -e ".[dev,mcp]"
```

## Tests and lint (both are required CI gates)

```bash
python -m pytest -q                         # full suite must pass
python -m ruff check --select F src tests   # no unused imports / F-errors
```

## Pull-request flow

1. Fork/branch from `main` (never commit to `main` directly).
2. Make focused commits using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(report): ...`, `fix(cli): ...`, `docs: ...`, `test: ...`, `refactor: ...`.
3. **Sign off every commit (DCO).** We use the [Developer Certificate of
   Origin](https://developercertificate.org/). Add `-s` to each commit:
   `git commit -s -m "feat: ..."` which appends `Signed-off-by: Your Name <you@example.com>`.
4. Open a PR; one maintainer review is required. PRs are merged with a merge
   commit or rebase (we do not squash).

## What makes a good PR

- Tests for any behavior change (we practice TDD where practical).
- No new runtime dependencies without prior discussion in an issue.
- User-facing changes get a line in `CHANGELOG.md` under `Unreleased`.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — never open a public issue for vulnerabilities.
