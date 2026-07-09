# Venom — Supply Chain Security & Health Platform
### Full Project Specification & Build Reference

**Status:** Ready to build
**Audience:** You (for reference and interview/portfolio explanation) and Claude Code (for implementation)

---

## 1. What This Is, In One Paragraph

Venom answers one question: *"Can I trust every piece of code my project depends on?"* It does this at three moments — **before** you install a package (the Bouncer), **continuously** while you work (the health score and live checks), and **automatically** on every commit and pull request (CI enforcement). It ships as a CLI, an IDE plugin, and a CI action, all three powered by the same detection engine, so nothing is duplicated and every improvement to the core logic improves all three surfaces at once.

---

## 2. Why This Exists (The Problem)

Modern software is built almost entirely out of other people's code. A small app with 500 lines of your own code can easily pull in 800+ third-party packages once you count dependencies-of-dependencies (transitive dependencies). Each of those packages was written by a stranger, is maintained (or not) by a stranger, and can be updated by that stranger at any time — and your project will automatically pull in whatever they push.

This creates two categories of risk:

1. **Known risk** — a package has a publicly reported security bug (a CVE) and you're running the vulnerable version.
2. **Unknown/emerging risk** — a package is actively malicious right now (a supply chain attack) and hasn't been caught yet. Examples: `event-stream` (2018, a maintainer handed off a popular package to an attacker who added crypto-stealing code), and the `xz` backdoor (2024, a two-year social-engineering campaign to insert a backdoor into a core Linux compression library, caught by accident).

Most existing tools (`npm audit`, Dependabot, Snyk) only address known risk. Venom addresses both, and — critically — is honest about the fact that active attacks are rare in any single project. Because of that honesty, Venom is designed to be **useful on every single run**, not just the rare run where it catches something scary. See Section 5 for how that shapes the whole design.

---

## 3. Product Philosophy (Read This Before Building Anything)

Three principles govern every design decision in this spec. When in doubt, check a feature idea against these before adding it.

### 3.1 Bouncer, not janitor
A janitor cleans up messes after they happen. A bouncer stops the problem at the door. Every other supply-chain tool on the market is a janitor — it scans what's already installed and tells you to clean it up. Venom's differentiator is catching risk **before** a package is installed, because that's the only moment where saying "no" costs the developer nothing. After install, every fix is cleanup: rewritten imports, re-tested code, rotated secrets. Before install, it's just a choice not to type `y`.

### 3.2 Useful every time, not just when something's wrong
If Venom only had value when it caught an active attack, it would be silent 95% of the time and feel pointless. So the product is framed as a **continuous health checkup**, like a doctor's visit — most visits don't find cancer, but they still produce a blood pressure reading, a cholesterol number, and a "here's what to improve" note. Every run of Venom produces a Health Score and a set of concrete, actionable findings, whether or not anything is actively malicious.

### 3.3 One engine, three surfaces
The CLI, the IDE plugin, and the CI action are not three separate products. They are three different windows into the same detection engine. A detection improvement made once (a better entropy threshold, a wider homoglyph table) automatically improves all three. This keeps the codebase from becoming three things to maintain — it's one thing to maintain, rendered three ways.

---

## 4. The Five Core Modules

These are the five underlying capabilities. Everything else in the product (the Bouncer, the Health Score, the plugin, the CI action) is a different way of *presenting or timing* these five modules — none of them are a sixth thing bolted on.

### Module 1 — Dependency Inventory ("What's actually in my project?")

**What it does:** Reads the project's lockfile (`package-lock.json`, `requirements.txt`, `poetry.lock`, etc.) and builds the complete dependency tree — direct dependencies plus every transitive dependency, however many layers deep.

**Output:** A Software Bill of Materials (SBOM) — a complete, structured list of every package and exact version in the project, similar in spirit to an ingredients list on food packaging. Supports two industry-standard formats:
- **SPDX** — the format preferred by government and enterprise compliance teams.
- **CycloneDX** — the format preferred by security tooling (SARIF-adjacent ecosystems, dependency-track, etc.).

Supporting both means the SBOM can be consumed by whatever downstream compliance or security tool the user's organization already uses.

**Why it matters standalone:** The 2021 US federal executive order on cybersecurity requires SBOMs for any software sold to the federal government. Even outside government contexts, "what do I actually have installed" is a question almost no developer can answer off the top of their head, and it's the foundation every other module depends on.

### Module 2 — Known Vulnerability Scanning ("Does anything have a known security bug?")

**What it does:** Takes the dependency inventory from Module 1 and checks every package+version against public vulnerability databases.

**Key concepts:**
- **CVE (Common Vulnerabilities and Exposures):** A unique ID for a specific, publicly disclosed security bug (e.g., `CVE-2024-38816`).
- **CVSS (Common Vulnerability Scoring System):** A 0.0–10.0 severity score. Above ~9.0 typically means remote, unauthenticated compromise is possible. Below ~4.0 typically means limited impact requiring existing access.
- **CISA KEV (Known Exploited Vulnerabilities catalog):** A US government list of CVEs that are being actively exploited *right now*, in the wild — not theoretical. A CVE appearing here is treated as maximum priority regardless of its CVSS score.
- **OSV.dev:** A free, Google-run API that aggregates vulnerability data from NVD, GitHub Security Advisories, and language-specific databases into a single queryable source. This is the primary data source for Module 2 — one API call per package instead of five.

**Why it fires constantly:** This is the module that produces findings on nearly every run of Venom against a real project. The ecosystem moves too fast for any team to manually track every CVE across hundreds of transitive dependencies — this is the bread-and-butter, always-useful core of the tool.

### Module 3 — Malicious Package Detection ("Is anything secretly malicious?")

This is the module that makes Venom unique, and it's the engine behind the Bouncer (Section 6). It catches problems that **haven't been reported yet** — Module 2 only catches known bugs; this module looks for the behavioral and structural fingerprints of an attack in progress.

**Detection techniques:**

- **Typosquatting detection (Levenshtein distance):** Attackers register a package with a name nearly identical to a popular one (`reqeusts` vs. `requests`), betting on developer typos. Levenshtein distance measures how many single-character edits separate two strings — a small distance between an unknown package and a hugely popular one is a strong red flag. This is a simple, well-understood algorithm.

- **Homoglyph detection:** Some characters from different alphabets are visually indistinguishable — the Latin `a` and the Cyrillic `а` look identical but are different Unicode code points. An attacker can register a package name that *looks* legitimate but isn't, character-for-character. Detection works by flagging any package name containing mixed Unicode scripts.

- **Maintainer risk scoring:** Every package is maintained by an account (or accounts) that can push updates at any time. Risk factors: a single maintainer with no backup (a single point of compromise or burnout-driven handoff, exactly how `event-stream` was attacked), a recent ownership/maintainer change on an established package, or a maintainer account that also owns other flagged packages.

- **Install script inspection:** Package managers allow a package to run arbitrary scripts automatically during installation (`postinstall` hooks, etc.). Legitimate uses exist (compiling native bindings), but this is also the single most common vector for malicious payloads — downloading a second-stage payload, exfiltrating environment variables (where API keys and tokens live), or establishing persistence. Venom downloads the package **without executing it**, reads any install scripts as plain text, and pattern-matches against known-dangerous constructs (network calls, environment variable access, obfuscated `eval`, etc.).

- **AST-based static analysis:** Rather than searching source code as raw text (fragile — easily evaded by formatting tricks), Venom parses the code into an Abstract Syntax Tree (AST) — a structured representation where a function call becomes a `CallExpression` node, a variable assignment becomes an `AssignmentExpression` node, etc. This lets Venom ask precise structural questions like "find every call to `exec`, `eval`, or `require('child_process')` regardless of how the surrounding code is formatted or obfuscated."

- **Shannon entropy analysis:** A mathematical measure of randomness in data. Normal source code and English text sit around 4.0–4.5 bits of entropy per character, because language and code both have predictable patterns. Base64-encoded encrypted or compressed payloads sit around 5.5–6.0+ bits, because they look like structureless noise. A source file with an entropy spike is a strong signal that it contains an encoded/encrypted blob that has no business being in source code — a common way malware hides its payload from casual review.

**Why this doubles as the Bouncer engine:** All of the above techniques work identically whether pointed at an *already-installed* package (janitor mode, run across the full dependency tree) or a *candidate* package someone is about to install (bouncer mode, run against a single name before it ever touches disk). See Section 6.

### Module 4 — Secrets Detection ("Did I accidentally leak a password?")

**What it does:** Scans both the current state of the codebase and the **entire git history** (every commit, every past version of every file) for accidentally committed credentials.

**Key concepts:**
- **Pattern matching:** Most credential types have a recognizable format — AWS access keys start with `AKID`, GitHub personal access tokens start with `ghp_`, Stripe live secret keys start with `sk_live_`. Venom matches against 100+ known patterns to identify not just *that* something looks like a secret, but *what kind* of secret it is.
- **Full git history scanning:** Git never truly deletes anything — every past commit remains recoverable. A secret committed and removed in the very next commit is still permanently exposed to anyone who clones the repo, unless the history itself is rewritten. Venom walks the entire commit history, not just the current working tree.
- **k-anonymity password breach checking:** To check whether a discovered password has appeared in known public breaches (via the Have I Been Pwned API) without ever sending the actual password over the network: hash the password locally, send only the **first 5 characters** of the hash to the API, receive back every known breached hash sharing that prefix, and check locally whether the full hash appears in that list. The real password never leaves the machine — a privacy-preserving protocol worth understanding on its own merits.

### Module 5 — Reporting & Remediation ("What do I actually do about all this?")

Most security tools are excellent at finding problems and terrible at helping anyone act on them. Module 5 is the difference between a wall of 200 raw findings and a tool a developer actually wants to open.

**Components:**
- **SARIF output** (Static Analysis Results Interchange Format): the industry-standard JSON format for reporting static analysis findings. Emitting SARIF means GitHub automatically renders Venom's findings in a repo's native Security tab, and GitLab/Azure DevOps support the same format — this is what makes Venom speak the same language as enterprise tooling rather than being a one-off script with proprietary output.
- **Pre-commit hooks:** A script that runs automatically on every `git commit` attempt and can block the commit outright — e.g., if a secret is detected in the staged files.
- **GitHub Action / CI integration:** Runs automatically on every pull request, posts findings as a PR comment, and can be configured to block merges above a configured risk threshold.
- **The Update Planner:** Rather than dumping "34 packages are outdated," updates are grouped by risk tier — **safe** (patch-level, no breaking changes), **recommended** (minor version, fixes a known CVE), **risky** (major version, likely breaking). Each entry shows what CVE it resolves, links the changelog, and shows ecosystem adoption of the new version as a signal of stability.

---

## 5. Features That Make Venom Useful on *Every* Run

These directly implement the "useful every time" philosophy from Section 3.2. None of these are new modules — each one is a specific lens applied to Modules 1–5.

| Feature | What it does | Draws from |
|---|---|---|
| **Supply Chain Health Score (0–100)** | A single composite number summarizing CVE exposure, dependency freshness, dependency tree depth, maintainer health, and secrets hygiene. Nobody gets 100 — the point is showing where a project stands and what would move the number. | Modules 1, 2, 3, 4 |
| **Score History** | Every run's score, CVE count, and secrets count is stored locally (SQLite) with a timestamp, turning a single snapshot into a trend line — "72 → 68 → 74 over the last month, here's what caused the dip." | Health Score, persisted over time |
| **Dependency Health Cards** | For every dependency: last update date, maintainer count, weekly download count (a rough proxy for "eyes on the code"), license, transitive dependency count, whether a security policy exists. | Modules 1, 3 |
| **Dependency Diff (CI mode)** | On every pull request, compares dependency state before/after: "+2 direct, +31 transitive, health score 78→74 because `some-lib` has 1 maintainer and hasn't updated in 14 months." | Modules 1, 3, Health Score |
| **Unused Dependency Detector** | Cross-references what's actually `import`ed/`require`d in source code against what's declared as a dependency. Flags dead weight — attack surface with zero benefit. | Module 1 + static source scan |
| **Update Planner** | See Module 5. | Module 5 |
| **`venom fix --safe`** | Executes the "safe" tier of the Update Planner automatically — patch-only version bumps with no CVE regression. Dry-run by default, shows a diff before applying anything. This is the difference between a linter and `eslint --fix`: detection without a "fix it" command is only half a product. | Module 5's existing categorization logic |
| **Secrets Hygiene Check** | Even with zero currently-leaked secrets: does `.gitignore` cover `.env`, `*.pem`, `*.key`, `credentials.json`? Is there a `.env.example` documenting required variables without real values? | Module 4 |
| **License Compliance Check** | Flags license conflicts and ambiguity — e.g., an MIT-licensed project depending on an AGPL-3.0 package (which can legally obligate open-sourcing the whole application), or dependencies with no declared license at all. | Module 1 |

---

## 6. The Bouncer — Full Design

The Bouncer is Module 3's detection logic (typosquat distance, homoglyph checks, entropy analysis, maintainer risk, install script inspection), pointed at a **candidate** package before it's installed rather than at an already-installed one. It is the single highest-leverage feature in the product because it's the only moment where a "no" is free.

It must exist in three places, because a bouncer that has to be manually remembered isn't really a bouncer:

### 6.1 CLI — `venom check <package>`
For deliberate evaluation of a new package. Output leads with a single verdict, then the supporting reasoning underneath:

```
✅ Clear        express@4.19.2

⚠️  Caution      some-lib@2.1.0
   → Single maintainer, no ownership change history
   → Last published 14 months ago
   → No install scripts detected

🚫 Flagged      reqeusts@1.0.3
   → Levenshtein distance 2 from "requests" (2.3M weekly downloads)
   → Package registered 6 days ago
   → Install script contains a network call to an unrecognized domain
```

### 6.2 IDE Plugin — real-time interception (the actual bouncer)
This is the surface that matters most, because it removes the step of the developer having to remember to ask. A CLI command only helps if someone runs it *before* installing — most people won't reliably do that on their own. The plugin intercepts at the moment of intent:

- **Live manifest watching:** the moment a new package name is saved into `package.json` / `requirements.txt`, or an install command is run from the integrated terminal, the same check fires automatically.
- **Inline diagnostics:** rendered as standard linter-style squiggles directly on the line where the package was added — red for Flagged, yellow for Caution, nothing for Clear. No new UI paradigm for the developer to learn.
- **Hover for detail:** the same reasoning shown in the CLI output, available on hover instead of requiring a separate command.
- **Command palette action** — `Venom: Check before install` — for checking a name before it's even typed into a manifest (e.g., pasted from a tutorial, a Stack Overflow answer, or AI-generated code).
- Uses the exact same detection engine as the CLI and CI action — no separate logic to maintain.

### 6.3 Pre-install / pre-commit hook — the safety net
Catches the cases where nobody was looking at the IDE — installing from a separate terminal, a script, or a CI pipeline. Same check, run automatically, configurable to hard-block on `🚫 Flagged` or warn-only on `⚠️ Caution`.

---

## 7. The IDE Plugin — Full Feature Set

The plugin is a first-class product surface, not an afterthought — it's the "always-on" view of everything the CLI can report, plus the Bouncer's real-time interception from Section 6.2.

- **Status bar health score:** the same number the CLI produces, always visible, click-to-expand into a full dependency audit panel inside the editor.
- **Inline bouncer diagnostics:** see 6.2.
- **Unused-dependency inline hints:** since the plugin already watches the file tree and import statements, dependencies never actually imported anywhere are grayed out / flagged directly in the manifest file.
- **Update Planner sidebar panel:** same safe/recommended/risky grouping as the CLI, with a one-click action per package that runs the same logic as `venom fix`.
- **Secrets hygiene warnings in the source control panel:** surfaced right where the developer is about to stage files for commit — same moment-of-intent principle as the Bouncer, applied to Module 4.

**Engineering note:** every one of the above is a rendering layer over an existing module — the plugin should be architected as a thin client against the same core detection library used by the CLI (see Section 9), not a reimplementation.

---

## 8. Who Uses This and When (Concrete Scenarios)

- **Individual developer, before deploying:** runs `venom audit .` the way they'd run a linter — not because they suspect something's broken, but as a standard pre-deploy habit.
- **Individual developer, evaluating a new package:** `venom check some-package`, or just watches for the plugin's inline diagnostic the moment they add it to `package.json`.
- **Individual developer, inheriting a codebase:** runs a full audit on day one to understand what they've inherited.
- **Team, in CI:** every pull request gets an automatic dependency health check. A policy file (`.venom.yml`) encodes the team's standards — no critical CVEs, no single-maintainer packages in production dependencies, no secrets in code — and Venom enforces it automatically. This is "policy as code," the same model real security engineering teams use.
- **Open-source maintainer:** uses SBOM generation for compliance requests, and displays the health score as a README badge ("Supply Chain Health: 91/100") alongside existing build/coverage badges — a genuine and growing trend in OSS.
- **Security-conscious organizations (government, defense, healthcare):** need a fully local, zero-telemetry tool — nothing about the codebase or dependency list is ever transmitted anywhere except the minimal, anonymous public API lookups (OSV.dev queries by package name/version, k-anonymity-protected HIBP checks). This is a genuine gap in a market where most competitors are cloud-SaaS tools.

---

## 9. Technical Architecture

### 9.1 High-level components

```
┌─────────────────────────────────────────────────────────────┐
│                      Core Detection Engine                   │
│  (language-agnostic library — the single source of truth)    │
│                                                              │
│  Module 1: Inventory      Module 2: Known Vulns              │
│  Module 3: Malicious Pkg  Module 4: Secrets                 │
│  Module 5: Report/Remediate                                  │
└───────────┬─────────────────┬─────────────────┬─────────────┘
            │                 │                 │
      ┌─────┼─────┐   ┌───────┼──────┐   ┌──────┼──────┐
      │    CLI    │   │  IDE Plugin  │   │  CI Action  │
      │ (venom …) │   │ (VS Code)    │   │ (GitHub)    │
      └───────────┘   └──────────────┘   └─────────────┘
```

The engine must be built as an independently invokable library/module (not embedded inline in the CLI) from day one — the CLI, plugin, and CI action are all callers of it, never reimplementations of it.

### 9.2 Suggested tech stack

- **Core engine:** Python (rich ecosystem for AST parsing, entropy calculation, package registry APIs) or Node/TypeScript (native fit for npm ecosystem, single language across CLI + VS Code plugin). **Recommendation: TypeScript** — VS Code plugins are TypeScript-native, and this avoids a language boundary between the plugin and the engine.
- **CLI:** Node CLI (`commander` or `yargs`), packaged and published to npm.
- **Local storage (score history, cache of API lookups):** SQLite (via `better-sqlite3` or similar) — no server required, fully local, matches the zero-telemetry design goal.
- **IDE Plugin:** VS Code extension API, TypeScript, communicating with the core engine as a local library import (not a network call).
- **CI Action:** GitHub Action (composite or Docker-based), invoking the same CLI under the hood.
- **External data sources:**
  - OSV.dev API — vulnerability data (Module 2)
  - npm registry API / PyPI JSON API — package metadata, maintainer info, publish dates (Modules 1, 3)
  - Have I Been Pwned API (k-anonymity range queries) — breached password checks (Module 4)
  - GitHub API — repo metadata for maintainer/security-policy checks (Module 3)

### 9.3 Data flow for a typical `venom audit` run

1. Locate and parse the lockfile — build dependency tree (Module 1).
2. For every package+version in the tree, query OSV.dev — collect CVEs, cross-reference CISA KEV (Module 2).
3. For every package, compute maintainer risk, typosquat distance against a popularity-ranked package list, entropy scan of source files, AST scan of install scripts (Module 3).
4. Scan working tree + full git history for secret patterns; for any password-like secrets found, run k-anonymity check against HIBP (Module 4).
5. Aggregate all of the above into: Health Score, SBOM (SPDX + CycloneDX), SARIF report, Update Plan, Unused Dependency list, License report (Module 5 + Section 5 features).
6. Persist score + summary metrics to local SQLite for history tracking.
7. Render to terminal (CLI), or emit SARIF/JSON (CI), or push into the plugin's panels (IDE).

---

## 10. CLI Command Reference (Target Surface)

```
venom audit .                 Full audit of the current project (all 5 modules + Section 5 features)
venom check <package>         Bouncer check on a candidate package before installing
venom fix --safe              Apply safe-tier updates only (dry-run by default)
venom fix --safe --apply      Actually apply safe-tier updates
venom sbom --format spdx      Generate SBOM in SPDX format
venom sbom --format cyclonedx Generate SBOM in CycloneDX format
venom score                   Print current health score + trend from local history
venom unused                  List declared-but-unused dependencies
venom licenses                License compliance report
venom secrets                 Secrets scan (working tree + full git history)
venom ci                      CI-mode output (SARIF + exit code for pass/fail gating)
venom init                    Generate a starter .venom.yml policy file
```

---

## 11. CI/CD Integration

- Emits SARIF, automatically surfaced in GitHub's native Security tab — no custom dashboard needed for basic adoption.
- `.venom.yml` policy file defines team standards, e.g.:

```yaml
policy:
  max_cvss_severity: 7.0        # block merges introducing a CVE above this score
  block_on_kev: true            # always block if CISA KEV-listed, regardless of score
  min_maintainers: 1            # warn (not block) below this
  block_on_secrets: true
  license_denylist: [AGPL-3.0]
```

- On every PR: run dependency diff (Section 5), post findings as a PR comment, apply the policy file's pass/fail gating.

---

## 12. Output Formats — Why Each One Exists

| Format | Purpose | Consumed by |
|---|---|---|
| **SPDX** | Government/enterprise compliance SBOM standard | Legal/compliance teams, federal contract requirements |
| **CycloneDX** | Security-tooling-oriented SBOM standard | Dependency-Track, other SCA tooling |
| **SARIF** | Standardized static-analysis findings format | GitHub/GitLab/Azure DevOps native security tabs |
| **JSON (internal)** | Raw structured output for the IDE plugin and custom tooling | Venom's own plugin, scripting/automation |

---

## 13. Demo Strategy (For Portfolio/Interview Use)

Build a small set of curated demo repositories that each isolate one capability:
1. A repo with intentionally planted secrets in git history (deleted in a later commit, still recoverable).
2. A repo with outdated dependencies carrying real, documented CVEs.
3. A repo with a typosquatting-style package name planted in the manifest.
4. A "clean-looking" repo that's actually unhealthy — deep dependency tree, single-maintainer packages, several unused dependencies.

Additionally, run Venom against real, well-known open-source projects (Express, Flask, etc.) to demonstrate it produces genuinely useful, non-contrived output on real-world code — proving the tool isn't just tuned to pass its own test fixtures.

---

## 14. What's Deliberately Out of Scope for V1

Keeping these out is what keeps the product a single coherent thing instead of a feature pile. Revisit only after the core (Modules 1–5 + Bouncer + plugin + CI) is solid and shipped.

- **Container/OS-level scanning** (Docker base images, OS packages) — a genuinely different trust boundary (OS packages vs. language-ecosystem packages) that would roughly double engineering surface for V1.
- **Additional language ecosystems** beyond npm and PyPI (e.g., Cargo, Go modules) — breadth before depth risks mediocrity everywhere instead of excellence in the two most common ecosystems.
- **JetBrains/other IDE plugins beyond VS Code** — ship one plugin well before multiplying maintenance surface.

---

## 15. Learning Path (Do Alongside Building, Not Strictly Before)

You don't need to become a security expert before starting — you need to understand the problem, the inputs, and the outputs well enough to make informed judgment calls (detection thresholds, false-positive tradeoffs) and to explain the project confidently in an interview. Implementation mechanics (exact API calls, parsing code) are what Claude Code handles during the build.

**Understand the problem space:**
- Search "event-stream npm attack explained" (YouTube) — the canonical maintainer-handoff attack.
- Search "xz utils backdoor explained" — the most sophisticated known supply-chain attack, caught by accident.
- Read a few posts on socket.dev/blog — accessible writeups of real, recent supply-chain attacks.

**Understand the inputs:**
- Browse osv.dev, search for a popular package (`lodash`, `requests`), read the vulnerability entries.
- Run `npm audit` or `pip-audit` on any real project you have.
- Paste some JavaScript into astexplorer.net to see AST parsing in action.
- Search "Levenshtein distance algorithm explained" (visual walkthroughs exist).
- Search "Shannon entropy explained simply."
- Check your own email at haveibeenpwned.com and read their k-anonymity API docs.

**Understand the outputs:**
- Read NTIA's "SBOM at a Glance" one-pager.
- Look at a sample SARIF file in GitHub's docs ("uploading a SARIF file to GitHub").
- Read the CycloneDX format overview at cyclonedx.org.
- Search "git hooks explained" and try setting up a basic pre-commit hook on any repo.
- Search "GitHub Actions beginner tutorial" and build a trivial one to understand the mechanism.

Whenever Claude Code produces a piece of a module you don't fully follow during the build, pause and spend ~20 minutes on that specific concept before moving on. Learning happens alongside building, not strictly before it.

---

## 16. The Pitch (For READMEs, Portfolios, Interviews)

> Venom gives developers complete visibility and control over their software supply chain. It stops risky packages *before* they're installed, continuously tracks the health of everything already installed, and enforces policy automatically in CI — all through one detection engine surfaced as a CLI, a VS Code plugin, and a GitHub Action. It generates industry-standard SBOMs, catches known CVEs, detects malicious packages before they're ever run, finds leaked secrets across full git history, and turns all of it into a prioritized, actionable remediation plan — entirely locally, with no telemetry.

This framing is deliberately honest: it does not claim to catch active attacks on every run (they're genuinely rare), and instead positions continuous supply-chain health as the core value, with attack prevention as one part of an always-useful whole.

---

## 17. Summary Checklist for Claude Code

When starting implementation, build in this order — each phase should be fully complete before moving to the next (no partial features):

1. **Core engine, Module 1** — lockfile parsing → dependency tree → SBOM (SPDX + CycloneDX).
2. **Core engine, Module 2** — OSV.dev integration, CVSS scoring, CISA KEV cross-reference.
3. **Core engine, Module 3** — typosquat distance, homoglyph detection, maintainer risk, install script inspection, AST scanning, entropy analysis. Design this module so it can run against either (a) the full installed tree or (b) a single candidate package name — this dual-mode requirement is what powers the Bouncer later with zero extra logic.
4. **Core engine, Module 4** — secrets pattern matching, full git history walk, HIBP k-anonymity integration.
5. **Core engine, Module 5** — SARIF output, Update Planner categorization, remediation command groundwork.
6. **Health Score + local SQLite history** — composite scoring across Modules 1–4, persisted per run.
7. **Section 5 features** — dependency health cards, dependency diff, unused-dependency detector, `venom fix --safe`, secrets hygiene check, license compliance check.
8. **CLI** — full command surface per Section 10, calling the engine as a library.
9. **Bouncer surfaces** — `venom check`, pre-commit/pre-install hook, using Module 3's dual-mode design.
10. **CI Action** — GitHub Action wrapping the CLI, `.venom.yml` policy parsing, PR comment posting, SARIF upload.
11. **VS Code Plugin** — status bar score, inline Bouncer diagnostics, unused-dependency inline hints, Update Planner sidebar, secrets hygiene warnings in source control panel — all as a thin client over the same core engine.
12. **Demo repos** — build the four curated demo repositories from Section 13, and validate against real open-source projects.
