import semver from 'semver';
import type { Ecosystem } from '../types/ecosystem';
import type { UpdateTier } from '../types/update';

/**
 * Compare two versions within an ecosystem. npm uses semver precisely; PyPI
 * (PEP 440) and anything non-semver fall back to a component-wise numeric compare.
 * Returns -1, 0, or 1.
 */
export function compareVersions(a: string, b: string, ecosystem: Ecosystem): number {
  if (ecosystem === 'npm' && semver.valid(a) && semver.valid(b)) {
    return semver.compare(a, b);
  }
  return numericCompare(a, b);
}

/**
 * Classify an upgrade into an {@link UpdateTier} by the size of the version jump:
 * patch → safe, minor → recommended, major → risky. `breaking` is true for major
 * jumps. This is what powers `venom fix --safe` (patch-only, no breaking changes).
 */
export function classifyBump(
  current: string,
  target: string,
  ecosystem: Ecosystem,
): { tier: UpdateTier; breaking: boolean } {
  if (ecosystem === 'npm' && semver.valid(current) && semver.valid(target)) {
    const diff = semver.diff(current, target);
    if (diff === 'major' || diff === 'premajor') return { tier: 'risky', breaking: true };
    if (diff === 'minor' || diff === 'preminor') return { tier: 'recommended', breaking: false };
    return { tier: 'safe', breaking: false }; // patch / prepatch / prerelease / same
  }

  const c = numericParts(current);
  const t = numericParts(target);
  if ((t[0] ?? 0) !== (c[0] ?? 0)) return { tier: 'risky', breaking: true };
  if ((t[1] ?? 0) !== (c[1] ?? 0)) return { tier: 'recommended', breaking: false };
  return { tier: 'safe', breaking: false };
}

/** True for pre-release / non-final versions (rc, beta, alpha, semver prerelease). */
export function isPrerelease(version: string, ecosystem: Ecosystem): boolean {
  if (ecosystem === 'npm' && semver.valid(version)) {
    return (semver.prerelease(version)?.length ?? 0) > 0;
  }
  return /[a-zA-Z]/.test(version.replace(/^v/, ''));
}

function numericParts(version: string): number[] {
  return version
    .replace(/^v/, '')
    .split(/[.\-_+]/)
    .map((p) => Number.parseInt(p, 10))
    .filter((n) => !Number.isNaN(n));
}

function numericCompare(a: string, b: string): number {
  const pa = numericParts(a);
  const pb = numericParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  // Equal numeric core: a version with a pre-release suffix sorts before the final.
  const aPre = /[a-zA-Z]/.test(a);
  const bPre = /[a-zA-Z]/.test(b);
  if (aPre !== bPre) return aPre ? -1 : 1;
  return 0;
}
