/**
 * Team standards encoded as code, loaded from `.venom.yml` (SPEC.md §11). The CI
 * action evaluates findings against this to decide pass/fail gating. All fields
 * optional; unset means "don't gate on this dimension".
 */
export interface Policy {
  /** Block merges introducing a CVE above this CVSS base score. */
  maxCvssSeverity?: number;
  /** Always block when a finding is CISA KEV-listed, regardless of score. */
  blockOnKev?: boolean;
  /** Warn (not block) when a production dependency has fewer maintainers than this. */
  minMaintainers?: number;
  /** Block when any secret is detected. */
  blockOnSecrets?: boolean;
  /** SPDX license identifiers that must not appear in the dependency tree. */
  licenseDenylist?: string[];
}
