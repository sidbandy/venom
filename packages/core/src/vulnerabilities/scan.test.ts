import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { createScanContext, type ScanContextHandle } from '../context';
import { VenomHttpClient } from '../net/http';
import { noopLogger } from '../logger';
import type { HttpClient, HttpRequestOptions } from '../types/context';
import type { DependencyGraph, DependencyNode } from '../types/graph';
import type { OsvVulnerability } from './osv';
import { scanVulnerabilities, summarizeVulnerabilities } from './scan';

interface FakeRoutes {
  vulnsByPackage: Record<string, string[]>;
  vulnDetails: Record<string, OsvVulnerability>;
  kev: string[];
}

/** A minimal HttpClient that answers OSV batch/detail and KEV requests from canned data. */
class FakeHttp implements HttpClient {
  constructor(private readonly routes: FakeRoutes) {}

  async getJson<T>(url: string): Promise<T> {
    if (url.includes('known_exploited_vulnerabilities')) {
      return { vulnerabilities: this.routes.kev.map((cveID) => ({ cveID })) } as T;
    }
    const detail = /\/v1\/vulns\/(.+)$/.exec(url);
    if (detail) return this.routes.vulnDetails[detail[1]!] as T;
    throw new Error(`unexpected getJson ${url}`);
  }

  async postJson<T>(url: string, body: unknown): Promise<T> {
    if (url.includes('/v1/querybatch')) {
      const { queries } = body as { queries: Array<{ package: { name: string } }> };
      return {
        results: queries.map((q) => ({
          vulns: (this.routes.vulnsByPackage[q.package.name] ?? []).map((id) => ({ id })),
        })),
      } as T;
    }
    throw new Error(`unexpected postJson ${url}`);
  }

  getText(_url: string, _opts?: HttpRequestOptions): Promise<string> {
    throw new Error('not used');
  }
  getBuffer(_url: string, _opts?: HttpRequestOptions): Promise<Buffer> {
    throw new Error('not used');
  }
}

function node(ref: DependencyNode['ref'], direct = true): DependencyNode {
  return { ref, direct, depth: 1, scopes: ['production'], dependencies: [], parents: [] };
}

function graphWith(...refs: DependencyNode['ref'][]): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  for (const ref of refs) nodes.set(`${ref.ecosystem}:${ref.name}@${ref.version}`, node(ref));
  return { root: { name: 'demo', version: '1.0.0', path: '/x' }, ecosystems: ['npm'], nodes };
}

const LODASH_CVE: OsvVulnerability = {
  id: 'GHSA-35jh-r3h4-6jhm',
  aliases: ['CVE-2021-23337'],
  summary: 'Command injection in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
  database_specific: { severity: 'HIGH' },
};

const handles: ScanContextHandle[] = [];
function makeCtx(http: HttpClient, offline = false): ScanContextHandle {
  const ctx = createScanContext({
    projectRoot: '/x',
    offline,
    http,
    cache: new SqliteCache(':memory:'),
    logger: noopLogger,
  });
  handles.push(ctx);
  return ctx;
}
afterEach(() => {
  for (const h of handles.splice(0)) h.dispose();
});

describe('scanVulnerabilities', () => {
  it('reports a vulnerable package with CVSS, KEV escalation, and remediation', async () => {
    const http = new FakeHttp({
      vulnsByPackage: { lodash: ['GHSA-35jh-r3h4-6jhm'], safe: [] },
      vulnDetails: { 'GHSA-35jh-r3h4-6jhm': LODASH_CVE },
      kev: ['CVE-2021-23337'],
    });
    const ctx = makeCtx(http);
    const graph = graphWith(
      { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
      { ecosystem: 'npm', name: 'safe', version: '1.0.0' },
    );

    const { vulnerabilities, findings } = await scanVulnerabilities(graph, ctx);

    expect(vulnerabilities).toHaveLength(1);
    const v = vulnerabilities[0]!;
    expect(v.id).toBe('GHSA-35jh-r3h4-6jhm');
    expect(v.aliases).toContain('CVE-2021-23337');
    expect(v.severity).toBe('high');
    expect(v.cvss?.baseScore).toBe(8.1);
    expect(v.knownExploited).toBe(true);
    expect(v.fixedVersions).toEqual(['4.17.21']);

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.level).toBe('error'); // high severity + KEV
    expect(f.ruleId).toBe('venom/CVE-2021-23337');
    expect(f.fingerprint).toBe('CVE-2021-23337::npm:lodash@4.17.20');
    expect(f.remediation).toContain('4.17.21');
    expect(f.locations[0]?.uri).toBe('pkg:npm/lodash@4.17.20');

    const summary = summarizeVulnerabilities(vulnerabilities);
    expect(summary).toMatchObject({ total: 1, knownExploited: 1 });
    expect(summary.bySeverity.high).toBe(1);
  });

  it('flags a known-malicious package (OSV MAL- advisory) as critical', async () => {
    const mal: OsvVulnerability = {
      id: 'MAL-2024-1234',
      summary: 'Package exfiltrates environment variables on install',
      affected: [{ package: { ecosystem: 'npm', name: 'evil-pkg' } }],
    };
    const http = new FakeHttp({
      vulnsByPackage: { 'evil-pkg': ['MAL-2024-1234'] },
      vulnDetails: { 'MAL-2024-1234': mal },
      kev: [],
    });
    const graph = graphWith({ ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' });

    const { vulnerabilities, findings } = await scanVulnerabilities(graph, makeCtx(http));
    expect(vulnerabilities[0]?.malicious).toBe(true);
    expect(vulnerabilities[0]?.severity).toBe('critical');
    expect(findings[0]?.ruleId).toBe('venom/malicious-package');
    expect(findings[0]?.category).toBe('malicious');
    expect(findings[0]?.title).toContain('KNOWN MALICIOUS PACKAGE');
  });

  it('serves cached vuln ids on a second run without re-querying', async () => {
    let batchCalls = 0;
    const http = new FakeHttp({
      vulnsByPackage: { lodash: ['GHSA-35jh-r3h4-6jhm'] },
      vulnDetails: { 'GHSA-35jh-r3h4-6jhm': LODASH_CVE },
      kev: [],
    });
    const wrapped: HttpClient = {
      ...http,
      postJson: async <T>(url: string, body: unknown, opts?: HttpRequestOptions): Promise<T> => {
        batchCalls += 1;
        return http.postJson<T>(url, body, opts);
      },
      getJson: http.getJson.bind(http),
      getText: http.getText.bind(http),
      getBuffer: http.getBuffer.bind(http),
    };
    const ctx = makeCtx(wrapped);
    const graph = graphWith({ ecosystem: 'npm', name: 'lodash', version: '4.17.20' });

    await scanVulnerabilities(graph, ctx);
    await scanVulnerabilities(graph, ctx);
    expect(batchCalls).toBe(1); // second run hit the cache
  });

  it('degrades to no findings in offline mode with a cold cache', async () => {
    const ctx = makeCtx(new VenomHttpClient({ offline: true }), true);
    const graph = graphWith({ ecosystem: 'npm', name: 'lodash', version: '4.17.20' });
    const { vulnerabilities } = await scanVulnerabilities(graph, ctx);
    expect(vulnerabilities).toEqual([]);
  });
});
