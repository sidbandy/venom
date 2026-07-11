# Venom GitHub Action

Run Venom's full supply-chain audit in CI: known CVEs (OSV + CISA KEV), malicious-package
signals, leaked secrets (working tree + git history), unused dependencies, and license
compliance — with `.venom.yml` policy-as-code gating, SARIF upload to the Security tab, and a
pull-request summary comment.

## Usage

```yaml
name: Supply Chain
on: [push, pull_request]

permissions:
  contents: read
  security-events: write # upload SARIF to the Security tab
  pull-requests: write # post the summary comment

jobs:
  venom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sidbandy/venom/action@main
```

Add a `.venom.yml` to your repo (run `venom init`) to enforce team policy:

```yaml
policy:
  max_cvss_severity: 7.0
  block_on_kev: true
  block_on_secrets: true
  license_denylist: [AGPL-3.0]
```

## Inputs

| Input            | Default       | Description                                        |
| ---------------- | ------------- | -------------------------------------------------- |
| `directory`      | `.`           | Project directory to scan.                         |
| `sarif-file`     | `venom.sarif` | Where to write the SARIF report.                   |
| `comment`        | `true`        | Post/update a summary comment on pull requests.    |
| `upload-sarif`   | `true`        | Upload SARIF to the GitHub Security tab.           |
| `fail-on-policy` | `true`        | Fail the job when `.venom.yml` policy is violated. |

The action is a composite that runs the same `venom` CLI used locally, so behavior is identical
everywhere (SPEC.md §3.3).
