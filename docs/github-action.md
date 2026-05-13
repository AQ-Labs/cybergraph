# GitHub Action

CyberGraph includes a workflow at `.github/workflows/cybergraph.yml` that turns the project into a pull-request security review helper.

## What it does

On pull requests and pushes to `main`, the workflow:

1. Installs CyberGraph from the repository checkout.
2. Builds the local security graph.
3. Runs `cybergraph review` for pull requests.
4. Exports `cybergraph.sarif`.
5. Generates `cybergraph-report.html`.
6. Uploads SARIF to GitHub code scanning.
7. Uploads the SARIF, HTML report, and review summary as workflow artifacts.

If code scanning is not enabled for the repository, the SARIF upload step is allowed to fail without failing the workflow. The SARIF file is still preserved as an artifact, so private repositories can use the workflow before code scanning is enabled.

## Required permissions

The workflow uses:

```yaml
permissions:
  contents: read
  security-events: write
  actions: read
```

`security-events: write` is required for SARIF upload.

## Local equivalent

```bash
cybergraph build .
cybergraph review --base main --repo .
cybergraph sarif --repo . --output cybergraph.sarif
cybergraph visualize . --output cybergraph-report.html
```

## Future improvement

The next useful addition is a PR comment step that posts the review summary directly into the pull request conversation.
