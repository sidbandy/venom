/**
 * The complete set of hosts Venom is ever permitted to contact. This list IS the
 * zero-telemetry guarantee (SPEC.md §8): a reviewer can audit every possible
 * network destination by reading this one file. Nothing about the user's code or
 * dependency list is ever sent anywhere else, and requests carry only the minimal
 * public identifiers (package name/version, or a k-anonymity hash prefix).
 *
 * Any attempt to reach a host outside this set throws {@link DisallowedHostError}.
 */
export const DEFAULT_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  // Module 2 — known vulnerabilities.
  'api.osv.dev',
  // CISA KEV catalog (known-exploited cross-reference).
  'www.cisa.gov',
  // Modules 1 & 3 — npm package metadata and tarballs.
  'registry.npmjs.org',
  // Modules 1 & 3 — PyPI package metadata (JSON API) and tarballs.
  'pypi.org',
  'files.pythonhosted.org',
  // Module 4 — Have I Been Pwned range API (k-anonymity; only a 5-char SHA-1 prefix leaves the machine).
  'api.pwnedpasswords.com',
  // Module 3 — GitHub repo metadata / security-policy checks.
  'api.github.com',
]);

/** Returns true if `host` is permitted. Matching is exact and case-insensitive. */
export function isAllowedHost(host: string, allowed: ReadonlySet<string>): boolean {
  return allowed.has(host.toLowerCase());
}
