# Venom

**Supply-chain security & health platform — a bouncer, not a janitor.**

Venom answers one question: _can I trust every piece of code my project depends on?_
It stops risky packages **before** they're installed, continuously tracks the
health of everything already in your tree, and enforces policy in CI — all through
one detection engine surfaced as a CLI, a VS Code plugin, and a GitHub Action.
Fully local, zero telemetry: the only network calls are anonymous public lookups
(OSV, the package registries, and HIBP via k-anonymity).

> See [`SPEC.md`](./SPEC.md) for the full product vision and [`future.md`](./future.md) for the roadmap.

## What works today

The full detection engine (Modules 1–5), a composite Health Score, and both the
CLI and CI surfaces are built and tested:

| Capability                    | What it does                                                                                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Inventory → SBOM**          | Parses npm (`package-lock.json` v1–3) and PyPI (`poetry.lock`, `requirements.txt`) into one dependency graph; emits deterministic **SPDX 2.3** and **CycloneDX 1.5**.                              |
| **Known vulnerabilities**     | OSV.dev batch queries, a from-scratch **CVSS 3.1** scorer, and **CISA KEV** escalation, with tiered remediation (`venom fix`).                                                                     |
| **Malicious-package Bouncer** | Typosquat (length-scaled edit distance), homoglyph, Shannon entropy, AST analysis, install-script inspection, maintainer risk — run against the whole tree _or_ a single candidate before install. |
| **Secrets**                   | ~22 credential patterns across the working tree **and full git history**, redacted, with **HIBP k-anonymity** breach checks (only a 5-char hash prefix ever leaves the machine).                   |
| **Health & policy**           | A composite **0–100 Health Score** with trend history, unused-dependency + license checks, SARIF output, and `.venom.yml` **policy-as-code** gating in CI.                                         |

Beyond the spec, Venom also does what the leading commercial tools charge for:

- **Reachability analysis** — CVEs in packages your code can't actually reach are de-prioritized and weighted less in the score.
- **Version-diff threat detection** (`venom diff`) — flags the event-stream/xz _update_ pattern: new maintainers, install scripts, dangerous code capabilities, or dropped build provenance between two versions.
- **Build-provenance verification** — detects signed source→artifact attestations (SLSA), the exact gap the xz backdoor exploited.
- **Known-malware detection** — recognizes OSV `MAL-…` malware advisories and flags the package as critical ("remove immediately").
- **API-surface report** (`venom api`) — groups your dependencies by the external service each SDK talks to (Stripe, OpenAI, AWS, …) with per-service CVEs, freshness, and leaked keys.
- **`venom install`** — the literal bouncer: vet, then install (or refuse).
- **Five lockfile formats** — npm, pnpm, Yarn Classic, Yarn Berry, and PyPI, all into one graph.
- **41 secret patterns**, CVSS v2 + v3.1 scoring, `--json`/`badge`/`--deterministic` output, and a `VenomError` code taxonomy.

## Try it

```bash
npm install && npm run build

# Full audit of a project (inventory + CVEs + package risk + secrets)
node packages/cli/dist/index.js audit /path/to/project

# Bouncer: vet a package before you install it (or vet-then-install)
node packages/cli/dist/index.js check expres          # 🚫 flags a typosquat of "express"
node packages/cli/dist/index.js install lodash        # vets, then runs npm install

# Version-diff: did this update turn malicious? (event-stream / xz pattern)
node packages/cli/dist/index.js diff lodash 4.17.20 4.17.21

# Health score with component breakdown + trend
node packages/cli/dist/index.js score .

# Tiered update plan (safe / recommended / risky)
node packages/cli/dist/index.js fix .

# Generate an SBOM
node packages/cli/dist/index.js sbom . --format cyclonedx

# Scan for leaked credentials (working tree + git history)
node packages/cli/dist/index.js secrets .

# Enforce .venom.yml policy and emit SARIF (CI gate)
node packages/cli/dist/index.js ci .
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

| Package           | Role                                                          |
| ----------------- | ------------------------------------------------------------- |
| `packages/core`   | `@venom/core` — the detection engine (single source of truth) |
| `packages/cli`    | `@venom/cli` — the `venom` command-line tool                  |
| `packages/vscode` | VS Code extension — the always-on in-editor surface           |
| `action/`         | Composite GitHub Action wrapping the CLI                      |

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

The full V1 scope is built and tested — the engine (Modules 1–5), the composite
Health Score + history, all three surfaces (CLI, VS Code extension, GitHub
Action), policy-as-code, and the four curated [demo repos](./demo/) — plus
several beyond-spec differentiators (reachability, version-diff, `venom install`,
pnpm/Yarn). Not yet published to npm/the Marketplace — see
[`future.md`](./future.md) for what's next (symbol-level reachability,
provenance/source↔artifact verification, AI-assisted triage).
