/**
 * Package ecosystems Venom supports in v1. Both npm and PyPI are first-class
 * from Module 1 onward, behind a single {@link EcosystemAdapter} contract so the
 * two never fork the rest of the engine (SPEC.md §14 scopes these two only).
 */
export type Ecosystem = 'npm' | 'pypi';

/**
 * An exact, resolved package coordinate. `version` is always a concrete version
 * (never a range) — ranges are resolved during inventory (Module 1).
 */
export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

/**
 * Stable identity for a resolved package, used as the key in a
 * {@link DependencyGraph} and as a dedup key throughout the engine.
 * Example: `npm:lodash@4.17.21`.
 */
export function packageKey(ref: PackageRef): string {
  return `${ref.ecosystem}:${ref.name}@${ref.version}`;
}
