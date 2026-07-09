import type { ScanContext } from '../types/context';
import type { Ecosystem, PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import { OfflineError } from '../net/errors';

const OSV_BASE = 'https://api.osv.dev';
/** OSV's batch endpoint accepts up to 1000 queries per request. */
const BATCH_LIMIT = 1000;
const IDS_TTL_MS = 24 * 60 * 60 * 1000; // vuln *membership* can change daily
const VULN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // vuln *details* rarely change

/** Raw OSV vulnerability record (the subset Venom consumes). */
export interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url: string }>;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  published?: string;
  modified?: string;
  /** Present (an ISO timestamp) when the advisory has been retracted. */
  withdrawn?: string;
}

export interface OsvAffected {
  package?: { ecosystem: string; name: string };
  ranges?: Array<{ type: string; events: Array<Record<string, string>> }>;
  versions?: string[];
}

interface OsvBatchResponse {
  results: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
}

/** OSV ecosystem identifiers differ from ours (`pypi` → `PyPI`). */
export function osvEcosystem(ecosystem: Ecosystem): string {
  return ecosystem === 'pypi' ? 'PyPI' : 'npm';
}

/**
 * Client for OSV.dev (SPEC.md §4 M2) — the aggregated vulnerability source.
 * Vulnerability *membership* per package is looked up via the batch endpoint
 * (cached per-package so repeat/offline runs reuse prior results and only cache
 * misses hit the network), and full vuln *details* are fetched once per unique id.
 */
export class OsvClient {
  /**
   * Map every package to the OSV vulnerability ids affecting it. Cache hits are
   * served locally; only uncached packages are queried, in batches of ≤1000.
   */
  async idsForPackages(refs: PackageRef[], ctx: ScanContext): Promise<Map<string, string[]>> {
    const result = new Map<string, string[]>();
    const misses: PackageRef[] = [];

    for (const ref of refs) {
      const key = packageKey(ref);
      const cached = ctx.cache.get<string[]>('osv-ids', key);
      if (cached) result.set(key, cached);
      else misses.push(ref);
    }

    for (let i = 0; i < misses.length; i += BATCH_LIMIT) {
      const chunk = misses.slice(i, i + BATCH_LIMIT);
      const ids = await this.#queryBatch(chunk, ctx);
      chunk.forEach((ref, idx) => {
        const key = packageKey(ref);
        const list = ids[idx] ?? [];
        ctx.cache.set('osv-ids', key, list, IDS_TTL_MS);
        result.set(key, list);
      });
    }

    return result;
  }

  /** Fetch full details for a single vulnerability id (cached long-term). */
  async getVuln(id: string, ctx: ScanContext): Promise<OsvVulnerability | null> {
    const cached = ctx.cache.get<OsvVulnerability>('osv-vuln', id);
    if (cached) return cached;
    try {
      const vuln = await ctx.http.getJson<OsvVulnerability>(`${OSV_BASE}/v1/vulns/${id}`);
      ctx.cache.set('osv-vuln', id, vuln, VULN_TTL_MS);
      return vuln;
    } catch (err) {
      if (err instanceof OfflineError) return null;
      ctx.logger.warn(`OSV: failed to fetch vulnerability ${id}: ${String(err)}`);
      return null;
    }
  }

  /** POST one batch of package queries; returns vuln-id lists aligned to input order. */
  async #queryBatch(refs: PackageRef[], ctx: ScanContext): Promise<string[][]> {
    const body = {
      queries: refs.map((ref) => ({
        package: { ecosystem: osvEcosystem(ref.ecosystem), name: ref.name },
        version: ref.version,
      })),
    };
    try {
      const res = await ctx.http.postJson<OsvBatchResponse>(`${OSV_BASE}/v1/querybatch`, body);
      return res.results.map((r) => (r.vulns ?? []).map((v) => v.id));
    } catch (err) {
      if (err instanceof OfflineError) {
        // Degrade: offline runs simply skip packages that were never cached.
        return refs.map(() => []);
      }
      ctx.logger.warn(`OSV: batch query failed: ${String(err)}`);
      return refs.map(() => []);
    }
  }
}
