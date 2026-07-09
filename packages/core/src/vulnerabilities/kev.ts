import type { ScanContext } from '../types/context';
import { OfflineError } from '../net/errors';

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_TTL_MS = 24 * 60 * 60 * 1000;

interface KevFeed {
  vulnerabilities?: Array<{ cveID?: string }>;
}

/**
 * The CISA Known Exploited Vulnerabilities catalog (SPEC.md §4 M2): CVEs being
 * actively exploited in the wild *right now*. A vulnerability appearing here is
 * treated as maximum priority regardless of its CVSS score. The catalog is
 * fetched once and cached for a day.
 */
export class KevCatalog {
  /** Load the set of KEV-listed CVE ids. Degrades to an empty set when offline. */
  async load(ctx: ScanContext): Promise<Set<string>> {
    const cached = ctx.cache.get<string[]>('kev', 'catalog');
    if (cached) return new Set(cached);
    try {
      const feed = await ctx.http.getJson<KevFeed>(KEV_URL);
      const ids = (feed.vulnerabilities ?? [])
        .map((v) => v.cveID)
        .filter((id): id is string => typeof id === 'string');
      ctx.cache.set('kev', 'catalog', ids, KEV_TTL_MS);
      return new Set(ids);
    } catch (err) {
      if (!(err instanceof OfflineError)) {
        ctx.logger.warn(`KEV: failed to load catalog: ${String(err)}`);
      }
      return new Set();
    }
  }
}
