import type { PackageRef } from '../types/ecosystem';

/**
 * Build a Package URL (purl) for a resolved package — the ecosystem-neutral
 * coordinate every SBOM format uses to identify a component
 * (https://github.com/package-url/purl-spec).
 *
 * Examples:
 *   - `npm:lodash@4.17.21`      → `pkg:npm/lodash@4.17.21`
 *   - `npm:@babel/core@7.26.0`  → `pkg:npm/%40babel/core@7.26.0`
 *   - `pypi:Flask@3.0.0`        → `pkg:pypi/flask@3.0.0`
 */
export function toPurl(ref: PackageRef): string {
  const version = encodeURIComponent(ref.version);
  if (ref.ecosystem === 'npm') {
    if (ref.name.startsWith('@')) {
      const slash = ref.name.indexOf('/');
      const scope = ref.name.slice(0, slash); // includes leading '@'
      const name = ref.name.slice(slash + 1);
      return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(name)}@${version}`;
    }
    return `pkg:npm/${encodeURIComponent(ref.name)}@${version}`;
  }
  // PyPI names are case-insensitive and treat runs of [-_.] as equivalent; the
  // purl spec requires the normalized (PEP 503) form.
  const normalized = normalizePypiName(ref.name);
  return `pkg:pypi/${encodeURIComponent(normalized)}@${version}`;
}

/** PEP 503 name normalization: lowercase, collapse runs of [-_.] to a single '-'. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}
