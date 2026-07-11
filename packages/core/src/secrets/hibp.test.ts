import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCache } from '../cache/sqlite-cache';
import { noopLogger } from '../logger';
import type { HttpClient, ScanContext } from '../types/context';
import { checkPassword } from './hibp';

const caches: SqliteCache[] = [];
afterEach(() => {
  for (const c of caches.splice(0)) c.close();
});

function sha1Upper(s: string): string {
  return createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
}

/** Records requested URLs and returns a canned HIBP range body. */
class RecordingHttp implements HttpClient {
  readonly urls: string[] = [];
  constructor(private readonly body: string) {}
  async getText(url: string): Promise<string> {
    this.urls.push(url);
    return this.body;
  }
  getJson<T>(): Promise<T> {
    throw new Error('not used');
  }
  getBuffer(): Promise<Buffer> {
    throw new Error('not used');
  }
  postJson<T>(): Promise<T> {
    throw new Error('not used');
  }
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

describe('checkPassword (HIBP k-anonymity)', () => {
  it('detects a breached password and sends only the 5-char hash prefix', async () => {
    const hash = sha1Upper('password');
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const http = new RecordingHttp(`${suffix}:37359\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n`);
    const ctx = ctxWith(http);

    const result = await checkPassword('password', ctx);
    expect(result).toEqual({ breached: true, count: 37359 });

    // The request URL must contain ONLY the prefix — never the suffix (the secret).
    expect(http.urls[0]).toContain(`/range/${prefix}`);
    expect(http.urls[0]).not.toContain(suffix);
  });

  it('reports a non-breached password as safe', async () => {
    const http = new RecordingHttp('0000000000000000000000000000000000A:5\n');
    const result = await checkPassword('an-extremely-unlikely-password-9f3a', ctxWith(http));
    expect(result.breached).toBe(false);
  });

  it('ignores padding entries (count 0)', async () => {
    const suffix = sha1Upper('padded').slice(5);
    const http = new RecordingHttp(`${suffix}:0\n`);
    const result = await checkPassword('padded', ctxWith(http));
    expect(result.breached).toBe(false);
  });
});
