import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { noopLogger } from '../logger';
import type { HttpClient, ScanContext } from '../types/context';
import { scanSecrets, summarizeSecrets } from './scan';

const exec = promisify(execFile);
const tmpDirs: string[] = [];
const caches: SqliteCache[] = [];

afterEach(async () => {
  for (const c of caches.splice(0)) c.close();
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const offlineHttp: HttpClient = {
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
    http: offlineHttp,
    cache,
    logger: noopLogger,
  };
}

async function git(root: string, ...args: string[]): Promise<void> {
  await exec('git', ['-C', root, ...args]);
}

async function initRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-secrets-'));
  tmpDirs.push(dir);
  await git(dir, 'init', '-b', 'main');
  await git(dir, 'config', 'user.email', 'test@venom.dev');
  await git(dir, 'config', 'user.name', 'Venom Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  return dir;
}

describe('scanSecrets (working tree + git history)', () => {
  it('finds a live secret in the tree and a removed one still in history', async () => {
    const dir = await initRepo();

    // A secret that stays in the working tree.
    await writeFile(join(dir, 'app.js'), 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
    await git(dir, 'add', 'app.js');
    await git(dir, 'commit', '-m', 'add app');

    // A secret committed and then removed — recoverable from history. The token is
    // assembled from parts so this test file contains no literal secret.
    const ghToken = `ghp_${'1234567890abcdefghijklmnopqrstuvwxyz'}`;
    await writeFile(join(dir, 'temp.js'), `const t = "${ghToken}";\n`);
    await git(dir, 'add', 'temp.js');
    await git(dir, 'commit', '-m', 'add temp');
    await git(dir, 'rm', 'temp.js');
    await git(dir, 'commit', '-m', 'remove temp');

    const { secrets, findings } = await scanSecrets(dir, ctx(), { breachCheck: false });

    const aws = secrets.find((s) => s.kind === 'aws-access-key');
    expect(aws).toBeDefined();
    expect(aws!.location.file).toBe('app.js');
    expect(aws!.location.inHistory).toBe(false);

    const gh = secrets.find((s) => s.kind === 'github-pat');
    expect(gh).toBeDefined();
    expect(gh!.location.inHistory).toBe(true);
    expect(gh!.location.commit).toMatch(/^[0-9a-f]{7,40}$/);

    // Redaction: the raw token must never appear in a finding.
    for (const f of findings) {
      expect(f.message).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(f.level).toBe('error');
    }

    const summary = summarizeSecrets(secrets);
    expect(summary.inWorkingTree).toBeGreaterThanOrEqual(1);
    expect(summary.inHistoryOnly).toBeGreaterThanOrEqual(1);
  });

  it('returns nothing for a clean repo', async () => {
    const dir = await initRepo();
    await writeFile(join(dir, 'readme.md'), '# clean project\n');
    await git(dir, 'add', '.');
    await git(dir, 'commit', '-m', 'init');
    const { secrets } = await scanSecrets(dir, ctx(), { breachCheck: false });
    expect(secrets).toEqual([]);
  });
});
