# Venom — Future Improvements & Ideas

A living backlog of enhancements, hardening, and feature ideas noticed during the
build. Kept separate from `SPEC.md` (the product definition) — this is the
"what next / what if" list. Updated as work progresses.

**Legend:** 🔴 high value · 🟡 medium · 🟢 nice-to-have · ✅ done

_Last updated: 2026-07-09 (after Module 2 — Known Vulnerability Scanning)._

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
