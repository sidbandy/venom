import type { PackageRef } from './ecosystem';

/**
 * Finding severity. These map 1:1 to SARIF `result.level` values so the SARIF
 * emitter (Module 5) is a mechanical projection with no severity remapping.
 */
export type FindingLevel = 'error' | 'warning' | 'note';

/** Which module/lens produced a finding — used for grouping and rule namespacing. */
export type FindingCategory =
  | 'vulnerability' // Module 2
  | 'malicious' // Module 3
  | 'maintainer-risk' // Module 3
  | 'secret' // Module 4
  | 'license' // Section 5
  | 'unused-dependency' // Section 5
  | 'hygiene'; // Section 5 (secrets hygiene, etc.)

/**
 * A location a finding points at. `uri` is a repo-relative file path for
 * source/secret findings, or a package coordinate (e.g. `pkg:npm/lodash@4.17.21`)
 * for dependency-level findings that have no single source line.
 */
export interface FindingLocation {
  uri: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

/**
 * The universal result type every module emits. Deliberately shaped to project
 * cleanly onto a SARIF `result` (SPEC.md §5, Module 5): `ruleId`, `level`,
 * `message`, `locations`, `properties`, and `fingerprint` (SARIF
 * `partialFingerprints`) all have direct SARIF counterparts.
 */
export interface Finding {
  /** Stable, namespaced rule id, e.g. `venom/typosquat`, `venom/cve`. */
  ruleId: string;
  level: FindingLevel;
  category: FindingCategory;
  /** Short one-line summary. */
  title: string;
  /** Full human-readable explanation. */
  message: string;
  locations: FindingLocation[];
  /**
   * Stable identity for deduplication and cross-run diffing (maps to SARIF
   * `partialFingerprints`). Two runs that find the same issue must produce the
   * same fingerprint so CI can tell "new" from "pre-existing".
   */
  fingerprint: string;
  /** The package this finding concerns, when applicable. */
  relatedPackage?: PackageRef;
  /** Actionable next step, surfaced in remediation output. */
  remediation?: string;
  /** Structured extras; rendered into SARIF `result.properties`. */
  properties?: Record<string, unknown>;
}
