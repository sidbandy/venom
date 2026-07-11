# Venom

**Supply-chain security & health platform — a bouncer, not a janitor.**

Venom answers one question: _can I trust every piece of code my project depends on?_
It stops risky packages **before** they're installed, continuously tracks the
health of everything already in your tree, and (soon) enforces policy in CI — all
through one detection engine surfaced as a CLI, a VS Code plugin, and a GitHub
Action. Fully local, zero telemetry: the only network calls are anonymous public
lookups (OSV, the package registries, and HIBP via k-anonymity).

> See [`SPEC.md`](./SPEC.md) for the full product vision and [`future.md`](./future.md) for the roadmap.

## What works today

The core detection engine is built and tested (Modules 1–4 of 5):

| Capability                    | What it does                                                                                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Inventory → SBOM**          | Parses npm (`package-lock.json` v1–3) and PyPI (`poetry.lock`, `requirements.txt`) into one dependency graph; emits deterministic **SPDX 2.3** and **CycloneDX 1.5**.                              |
| **Known vulnerabilities**     | OSV.dev batch queries, a from-scratch **CVSS 3.1** scorer, and **CISA KEV** escalation.                                                                                                            |
| **Malicious-package Bouncer** | Typosquat (length-scaled edit distance), homoglyph, Shannon entropy, AST analysis, install-script inspection, maintainer risk — run against the whole tree _or_ a single candidate before install. |
| **Secrets**                   | ~22 credential patterns across the working tree **and full git history**, redacted, with **HIBP k-anonymity** breach checks (only a 5-char hash prefix ever leaves the machine).                   |

## Try it

```bash
npm install && npm run build

# Full audit of a project (inventory + CVEs + package risk + secrets)
node packages/cli/dist/index.js audit /path/to/project

# Bouncer: vet a package before you install it
node packages/cli/dist/index.js check expres          # 🚫 flags a typosquat of "express"
node packages/cli/dist/index.js check flask -e pypi   # ✅ clear

# Generate an SBOM
node packages/cli/dist/index.js sbom . --format cyclonedx

# Scan for leaked credentials (working tree + git history)
node packages/cli/dist/index.js secrets .
```

## Use in CI

Enforce policy on every PR — SARIF goes to the Security tab, a summary is posted
as a comment, and the job fails on a `.venom.yml` violation:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  venom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sidbandy/venom/action@main
```

See [`action/`](./action/) for inputs and `venom init` to scaffold a policy.

## Architecture

An npm workspaces monorepo. The engine is a standalone library; every surface is
a thin caller over it, so a detection improvement lands everywhere at once
(SPEC.md §3.3, §9.1).

| Package         | Role                                                          |
| --------------- | ------------------------------------------------------------- |
| `packages/core` | `@venom/core` — the detection engine (single source of truth) |
| `packages/cli`  | `@venom/cli` — the `venom` command-line tool                  |
| `action/`       | Composite GitHub Action wrapping the CLI                      |

Security-first internals: a single audited network egress point with a host
allowlist and offline mode, safe download-without-execute package extraction
(zip-slip / bomb / symlink guards), ReDoS-conscious secret patterns, and
deterministic, schema-shaped output.

## Development

```bash
npm run build         # tsc project references across all packages
npm test              # vitest
npm run lint          # eslint (flat config, enforces the core API boundary)
npm run format        # prettier
```

## Status

🚧 Active development. Modules 1–4 of the core engine are complete and tested;
Module 5 (reporting/remediation), the composite Health Score, the CI Action, and
the VS Code plugin are next. Not yet published to npm.
