# Venom — Future Improvements & Ideas

A living backlog of enhancements, hardening, and feature ideas noticed during the
build. Kept separate from `SPEC.md` (the product definition) — this is the
"what next / what if" list. Updated as work progresses.

**Legend:** 🔴 high value · 🟡 medium · 🟢 nice-to-have · ✅ done

_Last updated: 2026-07-11 (after Module 5 — Reporting & Remediation)._

---

## Bigger bets — where Venom becomes category-leading

Beyond finishing the spec (see the phase plan), these are the differentiators that
would move Venom from "a good SCA tool" to something genuinely ahead of the market.

- 🔴 **Reachability analysis.** Most CVEs in transitive deps are never actually
  reachable from your code. Build a call graph and only escalate a vulnerability
  when the vulnerable symbol is truly invoked. This is the single biggest
  noise-reduction lever and what the leading commercial tools charge for — it
  turns "200 findings" into "the 4 that can actually hurt you."
- 🔴 **Version-diff threat detection ("what changed").** The real attacks
  (event-stream, xz) are _updates_ that turn a trusted package malicious. When a
  dependency bumps, diff the two versions: new maintainers, newly-added install
  scripts, new network calls, new native binaries, entropy spikes. Flag the delta,
  not the absolute state. Venom already computes all these signals per version.
- 🔴 **Provenance & source↔artifact verification.** Verify npm provenance / Sigstore
  attestations, and compare the published tarball against the upstream git tag —
  the exact gap the xz backdoor exploited (malicious code in the release tarball
  that wasn't in the repo). "This artifact does not match its source" is a killer
  signal nobody surfaces well.
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
- 🟡 **Live malicious-package feed.** Subscribe to the npm/PyPI malware advisory
  feeds and known-bad-package lists so Venom catches named, in-the-wild attacks
  instantly — not only what its heuristics infer.
- 🟢 **Blast-radius view & health badges.** Interactive graph of which features
  depend on a risky package (and what breaks if removed), plus a README
  `Supply Chain Health: 91/100` badge endpoint.
- 🟡 **API/SDK-dependency awareness.** Projects that lean on many third-party APIs
  (Stripe, OpenAI, Twilio, AWS, …) pull in the matching client SDKs — Venom already
  vets those packages for CVEs, malicious code, typosquats, and maintainer risk, and
  already catches their leaked keys (`sk_live_`, OpenAI, AWS, GitHub) in code + git
  history. Extend this into a first-class **"API surface" report**: group findings by
  the external service each SDK talks to, flag deprecated/outdated SDK major versions,
  detect hardcoded API base URLs pointing at look-alike/typosquatted domains, and warn
  when an SDK performs network calls at install time. (Live endpoint uptime/health is
  out of scope — that's runtime monitoring, a different product.)

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
- 🟡 **Deterministic default document identity.** SBOMs are reproducible only when
  a fixed `documentId`/`timestamp` is passed; the default uses a random UUID + now.
  Add a `--deterministic` flag (or derive the serial from a content hash) so
  default CI runs diff cleanly.
- 🟡 **Shared error taxonomy + exit codes.** Introduce a `VenomError` base with
  stable `code`s so the CLI maps failures to consistent exit statuses (distinct
  from the pass/fail _gating_ codes the CI phase will add).

## Detection & accuracy

- 🟡 **Expand the secret pattern set toward 100+.** The current registry is a
  strong ~22-pattern core; tools like gitleaks ship ~150. Add Azure, GCP service
  accounts, Heroku, Datadog, Twilio auth tokens, Square, Shopify, JWT-with-secret,
  and per-cloud session tokens. Also allowlist canonical documentation values
  (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`) so example code doesn't false-positive.
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
- 🟡 **CVSS v2 and v4 numeric scoring.** We compute v3.0/3.1 base scores precisely;
  v2/v4 vectors currently fall back to the advisory's qualitative severity label.
  Add the v2 and (more involved) v4 base-score formulas for full numeric coverage.
- 🟡 **Cross-ecosystem typosquat targets.** Typosquat checks compare a name only
  against its own ecosystem's popular list. `reqeusts` on npm should also flag
  against PyPI's `requests` (attackers impersonate famous names across registries).
  Feed a merged popular-name set into the check.
- 🟡 **Non-existent-package signal in the Bouncer.** When `venom check` finds no
  registry metadata (404 vs. transient error, disambiguated), surface it — a name
  that doesn't resolve is often a typo or a not-yet-published squat.
- 🟢 **Maintainer accounts for PyPI.** The JSON API doesn't expose maintainer
  accounts (only free-text author), so single-maintainer detection is npm-only
  today. Use an authenticated source or the web profile to get real PyPI
  maintainer counts.

## Ecosystem coverage (within the v1 language boundary)

- 🔴 **pnpm (`pnpm-lock.yaml`) and Yarn (`yarn.lock` classic + berry).** These are
  the same npm ecosystem (no new trust boundary vs. SPEC §14) and are common in
  real repos. Each is a new `EcosystemAdapter`-style lockfile parser feeding the
  existing npm graph — high real-world payoff, low architectural cost.
- 🟡 **More PyPI manifests:** `Pipfile.lock`, `uv.lock`, PDM's `pdm.lock`, and
  PEP 621 `[project]` metadata. All slot behind the existing `PypiAdapter`.

## Output & interoperability

- 🟡 **Richer SBOM fields.** Populate `hashes` (integrity is already in lockfiles),
  `licenses` (once license extraction lands, Section 5), and `externalReferences`
  (VCS/registry). SPDX: `PackageVerificationCode`, supplier/originator.
- 🟡 **Global `--json` output** for every command (not only `sbom`), for scripting
  and the IDE plugin — a stable machine-readable envelope around findings.
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
