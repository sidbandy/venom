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
export { ConsoleLogger, noopLogger } from './logger';
export type { LogLevel } from './logger';
export { createScanContext } from './context';
export type { CreateScanContextOptions, ScanContextHandle } from './context';

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
export { generateSarif, toSarif } from './report/sarif';
export type { SarifLog, SarifOptions } from './report/sarif';
export {
  buildUpdatePlan,
  applyNpmUpdates,
  compareVersions,
  classifyBump,
} from './remediation/index';
export type { UpdatePlanOptions, AppliedUpdate } from './remediation/index';

// Phase 6 — composite Health Score + local history.
export { computeHealthScore, ScoreHistoryStore } from './health/index';
export type { HealthInputs, HealthScoreOptions, ScoreRecord } from './health/index';

// Section 5 — cross-cutting analysis features.
export {
  detectUnusedDependencies,
  checkLicenses,
  checkSecretsHygiene,
  extractImports,
  packageNameOf,
  collectImportedPackages,
  computeReachablePackages,
} from './analysis/index';
export type { UnusedResult, LicenseResult, LicenseOptions, HygieneResult } from './analysis/index';

// The full audit pipeline — the single orchestration every surface calls.
export { auditProject } from './audit';
export type { AuditOptions, AuditResult } from './audit';

// Policy as code — `.venom.yml` loading + pass/fail evaluation (SPEC.md §11).
export { loadPolicy, STARTER_POLICY, evaluatePolicy } from './policy/index';
export type { PolicyEvaluation } from './policy/index';
export type { Policy } from './types/policy';

// Module 2 — Known Vulnerability Scanning.
export {
  scanVulnerabilities,
  summarizeVulnerabilities,
  OsvClient,
  KevCatalog,
  osvEcosystem,
  computeBaseScore,
  cvssFromVector,
  severityFromScore,
} from './vulnerabilities/index';
export type { VulnerabilityScanResult, OsvVulnerability } from './vulnerabilities/index';

// Module 3 — Malicious Package Detection (also powers the Bouncer, SPEC.md §6).
export {
  assessPackage,
  scanMalicious,
  checkCandidate,
  detectTyposquat,
  detectHomoglyphs,
  assessMaintainerRisk,
  inspectInstallScripts,
  scanSource,
  shannonEntropy,
  findHighEntropyTokens,
  levenshtein,
  popularNamesFor,
  diffVersions,
} from './malicious/index';
export type {
  BouncerVerdict,
  PackageAssessment,
  AssessOptions,
  MaliciousScanResult,
  ScanMaliciousOptions,
  TyposquatResult,
  HomoglyphResult,
  MaintainerRiskSignal,
  AstSignal,
  AstSignalKind,
  VersionDiff,
  DiffVerdict,
} from './malicious/index';

// Module 4 — Secrets Detection.
export {
  scanSecrets,
  summarizeSecrets,
  scanContent,
  scanWorkingTree,
  scanGitHistory,
  checkPassword,
  redact,
  SECRET_PATTERNS,
} from './secrets/index';
export type {
  SecretsScanResult,
  SecretsScanOptions,
  RawSecretMatch,
  FileSecretMatch,
  BreachResult,
  SecretPattern,
} from './secrets/index';
