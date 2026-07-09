/**
 * @venom/core — the Venom detection engine.
 *
 * This is the single public API surface for the engine. The CLI, the VS Code
 * extension, and the CI action are all callers of this package and must import
 * only from here — never from deep internal paths. Keeping the surface narrow is
 * what makes the "one engine, three surfaces" guarantee real (SPEC.md §3.3, §9.1).
 */

export const VERSION = '0.1.0';

// The domain model — the shared vocabulary of the engine.
export * from './types/index';

// Cross-cutting infrastructure callers use to build a ScanContext.
export { VenomHttpClient, DisallowedHostError, HttpError, OfflineError } from './net/index';
export type { VenomHttpClientOptions, FetchFn } from './net/index';
export { DEFAULT_ALLOWED_HOSTS } from './net/index';
export { SqliteCache } from './cache/index';

// Module 1 — Dependency Inventory & SBOM.
export {
  inventoryProject,
  defaultAdapters,
  NoSupportedLockfileError,
  buildDependencyGraph,
  summarizeGraph,
  NpmAdapter,
  PypiAdapter,
  toPurl,
  normalizePypiName,
} from './inventory/index';
export type { InventorySummary } from './inventory/index';
export { generateSbom, toSpdx, toCycloneDx } from './report/sbom/index';
export type { SbomFormat, SbomOptions, SpdxDocument, CycloneDxDocument } from './report/sbom/index';
