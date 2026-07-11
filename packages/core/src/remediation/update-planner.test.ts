import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { noopLogger } from '../logger';
import type { HttpClient, ScanContext } from '../types/context';
import type { DependencyGraph, DependencyNode } from '../types/graph';
import type { Vulnerability } from '../types/vulnerability';
import { buildUpdatePlan } from './update-planner';

const caches: SqliteCache[] = [];
afterEach(() => {
  for (const c of caches.splice(0)) c.close();
});

/** Fake npm registry: returns a canned packument for any package name requested. */
class FakeRegistry implements HttpClient {
  constructor(private readonly packuments: Record<string, unknown>) {}
  async getJson<T>(url: string): Promise<T> {
    const name = decodeURIComponent(url.split('/').pop() ?? '');
    const doc = this.packuments[name];
    if (!doc) throw new Error(`404 ${name}`);
    return doc as T;
  }
  getText(): Promise<string> {
    throw new Error('not used');
  }
  getBuffer(): Promise<Buffer> {
    throw new Error('not used');
  }
  postJson<T>(): Promise<T> {
    throw new Error('not used');
  }
}

function packument(versions: string[], latest: string): unknown {
  return {
    'dist-tags': { latest },
    versions: Object.fromEntries(versions.map((v) => [v, { version: v }])),
    time: { created: '2019-01-01T00:00:00Z', modified: '2024-01-01T00:00:00Z' },
    maintainers: [{ name: 'a' }, { name: 'b' }],
  };
}

function ctxWith(http: HttpClient): ScanContext {
  const cache = new SqliteCache(':memory:');
  caches.push(cache);
  return {
    projectRoot: '/x',
    config: { offline: false, dataDir: '/x' },
    http,
    cache,
    logger: noopLogger,
  };
}

function directNode(name: string, version: string): DependencyNode {
  return {
    ref: { ecosystem: 'npm', name, version },
    direct: true,
    depth: 1,
    scopes: ['production'],
    dependencies: [],
    parents: [],
  };
}

function graphWith(...nodes: DependencyNode[]): DependencyGraph {
  const map = new Map<string, DependencyNode>();
  for (const n of nodes) map.set(`${n.ref.ecosystem}:${n.ref.name}@${n.ref.version}`, n);
  return { root: { name: 'demo', version: '1.0.0', path: '/x' }, ecosystems: ['npm'], nodes: map };
}

describe('buildUpdatePlan', () => {
  it('proposes the minimal CVE-fixing version and tiers it', async () => {
    const http = new FakeRegistry({
      lodash: packument(['4.17.19', '4.17.20', '4.17.21', '4.18.0'], '4.18.0'),
    });
    const graph = graphWith(directNode('lodash', '4.17.20'));
    const vulns: Vulnerability[] = [
      {
        id: 'CVE-2021-23337',
        aliases: ['CVE-2021-23337'],
        severity: 'high',
        knownExploited: false,
        affected: { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
        fixedVersions: ['4.17.21'],
        references: [],
      },
    ];

    const plan = await buildUpdatePlan(graph, vulns, ctxWith(http));
    expect(plan).toHaveLength(1);
    // Prefer the minimal fix (4.17.21), not the latest (4.18.0).
    expect(plan[0]).toMatchObject({
      targetVersion: '4.17.21',
      tier: 'safe',
      fixesVulnerabilities: ['CVE-2021-23337'],
      breaking: false,
    });
  });

  it('proposes latest for an outdated but non-vulnerable dependency', async () => {
    const http = new FakeRegistry({ chalk: packument(['5.0.0', '5.3.0'], '5.3.0') });
    const graph = graphWith(directNode('chalk', '5.0.0'));
    const plan = await buildUpdatePlan(graph, [], ctxWith(http));
    expect(plan[0]).toMatchObject({
      targetVersion: '5.3.0',
      tier: 'recommended',
      fixesVulnerabilities: [],
    });
  });

  it('omits dependencies that are already current', async () => {
    const http = new FakeRegistry({ chalk: packument(['5.3.0'], '5.3.0') });
    const graph = graphWith(directNode('chalk', '5.3.0'));
    expect(await buildUpdatePlan(graph, [], ctxWith(http))).toEqual([]);
  });
});
