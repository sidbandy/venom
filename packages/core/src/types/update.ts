import type { PackageRef } from './ecosystem';

/**
 * Risk tier for a proposed dependency update (SPEC.md §4 M5, §5):
 * - `safe`        — patch-level, no breaking changes; eligible for `venom fix --safe`.
 * - `recommended` — minor version, typically resolves a known CVE.
 * - `risky`       — major version, likely breaking.
 */
export type UpdateTier = 'safe' | 'recommended' | 'risky';

export interface UpdatePlanEntry {
  /** The currently-installed package+version. */
  current: PackageRef;
  /** The version Venom proposes upgrading to. */
  targetVersion: string;
  tier: UpdateTier;
  /** Vulnerability ids this update resolves, if any. */
  fixesVulnerabilities: string[];
  /** True when the jump crosses a major version / documented breaking change. */
  breaking: boolean;
  changelogUrl?: string;
  /** Human-readable justification shown in the plan. */
  reason: string;
}
