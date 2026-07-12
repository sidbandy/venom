# Venom for VS Code

The always-on, in-editor surface of Venom — a thin client over the same
`@venom/core` engine as the CLI and the GitHub Action (SPEC.md §7).

## Features

- **Status-bar health score** — the same 0–100 score the CLI produces, color-coded,
  always visible. Click it to run a full audit.
- **The Bouncer, inline** — dependency names in `package.json` get linter-style
  squiggles: red for typosquats / homoglyphs, yellow for known CVEs, blue for
  unused (declared-but-never-imported) dependencies. Hover for the reason.
- **Pre-install check** — the `Venom: Check Package Before Install` command vets a
  package name (pasted from a tutorial, an answer, or AI-generated code) _before_
  it ever touches your manifest.
- **Audit workspace** — `Venom: Audit Workspace` runs the full pipeline and reports
  the breakdown in the Venom output channel.

Set `venom.offline` to run without any network calls.

## Development

```bash
npm run build           # from the repo root — compiles all packages incl. this one
```

Then press <kbd>F5</kbd> in VS Code with this folder open to launch an Extension
Development Host. (Automated tests for the extension require the VS Code test
harness; the detection logic it renders is fully unit-tested in `@venom/core`.)
