# Venom

Supply chain security & health platform. Bouncer, not janitor.

Venom catches risky packages **before** they're installed, continuously
tracks the health of everything already in your project, and enforces
policy automatically in CI — through one detection engine surfaced as a
CLI, a VS Code plugin, and a GitHub Action.

## Status

🚧 Early development. See [`SPEC.md`](./SPEC.md) for the full project specification.

## Layout

This is an npm workspaces monorepo. The engine is a standalone library; every
surface is a thin caller over it (SPEC.md §3.3, §9.1).

| Package         | Role                                                          |
| --------------- | ------------------------------------------------------------- |
| `packages/core` | `@venom/core` — the detection engine (single source of truth) |
| `packages/cli`  | `@venom/cli` — the `venom` command-line tool                  |

## Getting started

```bash
npm install          # install all workspaces
npm run build        # compile every package (tsc project references)
npm test             # run the vitest suite
npm run lint         # eslint
node packages/cli/dist/index.js audit
```
