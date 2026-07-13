# Venom — Future Improvements & Ideas

A living backlog of enhancements, hardening, and feature ideas noticed during the
build. Kept separate from `SPEC.md` (the product definition) — this is the
"what next / what if" list. Updated as work progresses.

**Legend:** 🔴 high value · 🟡 medium · 🟢 nice-to-have · ✅ done

_Last updated: 2026-07-13 (correctness-hardening pass: closed an ESM/dynamic-import
malware-detection gap, made reachability scoring conservative when it can't be
established, and fixed the single-maintainer false-caution)._

---

## Detection correctness — audit findings & fixes (2026-07-13)

A line-by-line correctness review of every checking algorithm (the priority: the
checks must be right, not just the output). Verified sound as-is: HIBP k-anonymity
(only the 5-char SHA-1 prefix ever leaves the machine), CVSS v2 + v3.1 scoring
(hand-checked against the spec), the bounded Levenshtein cutoff, OSV batch/version
alignment, the git-history hunk parser, and the secret-scanner's ReDoS-safe,
entropy-gated patterns. Three real issues were found and fixed with regression tests:

- ✅ **Malware AST scanner missed ESM.** `scanSource` only recognized
  `require('child_process')` — it did **not** flag `import`, `export … from`, or
  dynamic `import()` of dangerous modules, nor the obfuscated computed form
  `process['env']`. Modern (ESM) malware would have slipped past the module/exfil
  signals. Now all four import forms and computed env-access are detected; a benign
  ESM import (`node:fs/promises`) still yields nothing. _(ast-scan.ts)_
- ✅ **Reachability could deflate the score.** When the reachable set came back
  empty — a non-JS project, or unparseable source — every CVE was treated as
  "unreachable" and down-weighted 0.4×, making a vulnerable project look healthier.
  Reachability is now gated behind `reachabilityAnalyzed`: when it can't be
  established, CVEs are scored at full weight and the "reachable" count is omitted
  rather than reported as a misleading zero. _(audit.ts)_
- ✅ **Single-maintainer false-caution.** A lone maintainer is extremely common
  among trusted packages, yet it was a `warning` that forced a "caution" verdict
  (e.g. `@types/node`). Downgraded to a `note`: it's surfaced as context but only
  escalates to caution in combination with a genuinely alarming signal (brand-new
  or deprecated), so real event-stream-shaped risks still fire. _(maintainer-risk.ts)_

## Bigger bets — where Venom becomes category-leading

Beyond finishing the spec (see the phase plan), these are the differentiators that
would move Venom from "a good SCA tool" to something genuinely ahead of the market.

- ✅ **Reachability analysis (package-level).** Implemented: `computeReachablePackages`
  seeds from the direct dependencies the source actually imports and walks the
  resolved graph, so CVEs in packages your code can't reach are de-prioritized in
  the audit and weighted less in the Health Score. **Next refinement:** symbol-level
  (call-graph) reachability — escalate only when the vulnerable _function_ is
  invoked, the further noise-reduction lever the leading commercial tools charge for.
- ✅ **Version-diff threat detection ("what changed").** Implemented as
  `venom diff <pkg> <from> <to>` / `diffVersions`: downloads both versions
  (without executing), and flags the security-relevant delta — new maintainers
  (ownership handoff), newly-added/changed install scripts, newly-introduced code
  capabilities (child_process, eval, network, obfuscation), and entropy spikes.
  This catches the event-stream/xz _update_ pattern. **Next:** run it automatically
  in CI on every dependency bump (diff base vs PR lockfile).
- 🟡 **Provenance & source↔artifact verification.** Implemented: Venom detects
  whether an npm package was published with a signed build-provenance attestation
  (SLSA) and surfaces it in `venom check` (✓/·), and `venom diff` flags when a
  version _drops_ provenance it previously had. **Next:** fetch and cryptographically
  verify the attestation (Sigstore), and compare the published tarball against the
  upstream git tag — "this artifact does not match its source" is the exact xz gap.
- 🔴 **AI-assisted triage & explanation (optional, local-respecting).** An opt-in
  layer that explains a finding in plain English ("this RCE is reachable via your
  `parseConfig` call"), triages a wall of findings by real-world impact, and drafts
  the remediation. Keep it strictly opt-in to preserve the zero-telemetry promise.
- 🟡 **`venom install <pkg>` — the literal bouncer.** A package-manager wrapper that
  runs the Bouncer check and _then_ installs (or refuses). The Section-6 CLI check
  only helps if someone remembers to run it; wrapping the install command makes the
  bouncer unavoidable at the true moment of intent.
- 🟡 **Auto-remediation pull requests.** Beyond `fix --safe` dry-runs: open a PR that
  bumps vulnerable deps, embeds the CVE/changelog context, and runs the test suite —
  Dependabot-grade, but driven by Venom's reachability + risk model.
- 🟡 **Behavioral sandbox (dynamic analysis).** Execute install scripts inside an
  isolated sandbox (gVisor/Firecracker/container) and observe real syscalls and
  network egress — dynamic confirmation on top of the static AST/entropy signals.
- ✅ **Live malicious-package feed.** OSV aggregates the npm/PyPI malware advisories
  (`MAL-…`), and Venom already queries OSV — so Module 2 now recognizes those
  advisories, escalates the package to critical, and emits a distinct
  `venom/malicious-package` finding ("KNOWN MALICIOUS PACKAGE — remove immediately").
  Catches named, in-the-wild attacks, not just heuristic inference.
- 🟢 **Blast-radius view & health badges.** Interactive graph of which features
  depend on a risky package (and what breaks if removed), plus a README
  `Supply Chain Health: 91/100` badge endpoint.
- ✅ **API/SDK-dependency awareness.** Implemented as `venom api`: detects the
  third-party API client SDKs a project uses (Stripe, OpenAI, AWS, Twilio, Slack,
  GitHub, …, via an exact + scoped-prefix map) and groups them by external service,
  showing per-service SDK freshness, CVEs, and leaked credentials. **Next:** detect
  hardcoded API base URLs pointing at look-alike domains, and warn when an SDK runs
  network calls at install time.

---

## Near-term hardening (consciously deferred)

- 🔴 **Official JSON-schema validation of emitted SBOM/SARIF.** Today the emitters
  are covered by structural + referential-integrity tests. Bundling the official
  SPDX 2.3, CycloneDX 1.5/1.6, and SARIF 2.1.0 schemas and validating output with
  `ajv` (offline, no remote `$ref` fetches) would guarantee interoperability and
  is a strong portfolio signal. _Foundation is ready; this is a self-contained add._
- 🔴 **Concurrency + rate-limit helper.** Modules 2 & 3 fan out to OSV / npm /
  PyPI across hundreds of packages. Add a small `mapWithConcurrency(limit, …)`
  utility and prefer batch endpoints (OSV `/v1/querybatch`) before wiring those
  modules, so we never open 269 sockets at once.
- ✅ **Deterministic SBOM output.** `venom sbom --deterministic` derives the
  document id from a content hash of the sorted package set and uses a fixed
  timestamp, so repeated CI runs produce byte-identical SBOMs that diff cleanly.
- ✅ **Shared error taxonomy.** Implemented: a `VenomError` base with stable
  `code`s (`OFFLINE`, `DISALLOWED_HOST`, `HTTP_ERROR`, `TARBALL_SECURITY`,
  `NO_LOCKFILE`); every engine error extends it. **Next:** map codes to distinct
  CLI exit statuses.

## Detection & accuracy

- 🟡 **Expand the secret pattern set toward 100+.** Now **41 patterns** (added
  Shopify, Square, Postman, New Relic, Databricks, Doppler, Hugging Face, Linear,
  Figma, Telegram, Mailchimp, Terraform, PlanetScale, Supabase, Sentry, Azure
  Storage, RubyGems, Pulumi, Grafana, OpenAI project keys). Keep going toward the
  ~150 gitleaks ships. Canonical documentation values (AWS's `AKIAIOSFODNN7EXAMPLE`)
  are allowlisted so example code doesn't false-positive.
- 🟡 **Fingerprint-level `.venomignore` entries.** Today `.venomignore` matches
  file globs; add per-finding fingerprint suppression (like `.gitleaksignore`) so
  a single reviewed false positive can be silenced without excluding a whole file.
- 🟢 **Secret scan performance on huge histories.** `git log -p` is streamed, but
  every added line runs the full pattern set. For very large repos, pre-filter
  lines (cheap substring gate) before the regex battery, and/or shard by commit.
- 🔴 **Transitive resolution for `requirements.txt`.** Currently flat/pinned-only
  (honestly excludes unpinned and carries no edges). Resolve the full graph via
  the PyPI API or an installed-environment read; also handle `-r`/`-c` includes,
  `--hash`, extras, markers, and VCS/URL requirements.
- 🟡 **Full lockfileVersion 1 fidelity.** The v1 npm path approximates edges from
  `requires` without nearest-wins disambiguation of nested duplicate versions.
  Modern npm emits v2/v3 (fully supported), so this is legacy polish.
- 🟡 **VEX (Vulnerability Exploitability eXchange).** Emit/consume VEX so known-CVE
  findings can be annotated as not-exploitable-in-context — increasingly requested
  alongside SBOMs by enterprise consumers.
- 🟢 **Python AST scanning (Module 3).** Extend install-script/source analysis to
  Python (`setup.py`, `sitecustomize`, `.pth`) — not just JS via `@babel/parser` —
  so PyPI packages get the same structural scrutiny as npm.
- 🟡 **Section-5 analysis for PyPI + devDependencies.** The unused-dependency
  detector (JS/TS imports) and license check (node_modules read) are npm-only.
  Add Python import analysis + PyPI license metadata, and a heuristic for unused
  devDependencies (tools invoked via config, not `import`, are false positives today).
- 🟡 **Dependency health cards & PR dependency diff (remaining Section-5 items).**
  Health cards (last-update, maintainer count, weekly downloads, transitive count)
  fold naturally into `venom check` output and the VS Code hover; the before/after
  dependency diff belongs to the CI action (compare base vs PR graphs).
- 🟡 **CVSS v4 numeric scoring.** We now compute v2.0 and v3.0/3.1 base scores
  precisely (v2 detected even in its bare, prefix-less form via the `Au:` metric).
  v4's materially more complex scoring is the remaining piece.
- ✅ **Cross-ecosystem typosquat targets.** The Bouncer now matches against the
  union of npm + PyPI popular names, so `reqeusts` on npm flags against PyPI's
  `requests`.
- ✅ **Non-existent-package signal in the Bouncer.** `venom check` now flags a
  name that doesn't resolve in the registry (likely a typo or unpublished squat).
- 🟢 **Maintainer accounts for PyPI.** The JSON API doesn't expose maintainer
  accounts (only free-text author), so single-maintainer detection is npm-only
  today. Use an authenticated source or the web profile to get real PyPI
  maintainer counts.

## Ecosystem coverage (within the v1 language boundary)

- ✅ **pnpm + Yarn (Classic v1 **and** Berry v2+).** All feed the existing npm
  graph via lockfile parsers over a shared `working-graph` helper. So Venom now
  understands npm, pnpm, Yarn Classic, Yarn Berry, and PyPI (poetry/requirements)
  lockfiles — five formats, one graph.
- 🟡 **More PyPI manifests:** `Pipfile.lock`, `uv.lock`, PDM's `pdm.lock`, and
  PEP 621 `[project]` metadata. All slot behind the existing `PypiAdapter`.

## Output & interoperability

- 🟡 **Richer SBOM fields.** Populate `hashes` (integrity is already in lockfiles),
  `licenses` (once license extraction lands, Section 5), and `externalReferences`
  (VCS/registry). SPDX: `PackageVerificationCode`, supplier/originator.
- ✅ **`--json` audit output + `venom badge`.** `venom audit --json` emits the
  full result as JSON for scripting; `venom badge` outputs a shields.io endpoint
  JSON for a README `Supply Chain Health` badge. (Extending `--json` to every
  command is the small remaining piece.)
- 🟢 **SBOM signing / attestation** (Sigstore/cosign, in-toto) so a generated SBOM
  can be verified downstream.

## Engineering & ops

- 🔴 **Dogfood in CI.** Manual dogfooding already works — `venom audit` on Venom
  itself surfaces the 5 real advisories in its own dev tree (vite/vitest/esbuild),
  matching `npm audit`. Remaining: wire this into a CI workflow as a live check.
- 🟡 **Coverage reporting + gate** (vitest `--coverage` / c8) and a CI workflow
  running build + lint + format + test on PRs.
- 🟡 **Release provenance for Venom itself** (npm provenance / SLSA) — a security
  tool should model the supply-chain hygiene it preaches.
- 🟢 **Cross-platform test matrix** (Windows path handling in tarball extraction
  and lockfile parsing) once CI exists.

## Known limitations (tracked honestly)

- `requirements.txt` inventory is direct-and-pinned only (see above).
- Default SBOM output is non-reproducible unless identity is pinned (see above).
- The dependency graph is fully in-memory (`Map`) — fine to tens of thousands of
  nodes; revisit streaming only if a pathological monorepo demands it.
