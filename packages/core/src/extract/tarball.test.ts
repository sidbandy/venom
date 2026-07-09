import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createGzip } from 'node:zlib';
import { pack } from 'tar-stream';
import { describe, expect, it } from 'vitest';
import { extractTarball, TarballSecurityError } from './tarball';

interface FixtureEntry {
  name: string;
  type?: 'file' | 'directory' | 'symlink';
  content?: string;
  linkname?: string;
}

/** Build a gzip-compressed tar buffer from a set of entries, like a real .tgz. */
async function makeTgz(entries: FixtureEntry[]): Promise<Buffer> {
  const p = pack();
  const chunks: Buffer[] = [];
  const gz = p.pipe(createGzip());
  const collected = (async () => {
    for await (const chunk of gz) chunks.push(chunk as Buffer);
  })();

  const addEntry = (e: FixtureEntry): Promise<void> =>
    new Promise((res, rej) => {
      const done = (err: unknown): void => (err ? rej(err as Error) : res());
      if (e.type === 'directory') {
        p.entry({ name: e.name, type: 'directory' }, done);
      } else if (e.type === 'symlink') {
        p.entry({ name: e.name, type: 'symlink', linkname: e.linkname ?? '', size: 0 }, done);
      } else {
        const content = e.content ?? '';
        p.entry({ name: e.name, size: Buffer.byteLength(content) }, content, done);
      }
    });

  for (const e of entries) await addEntry(e);
  p.finalize();
  await collected;
  return Buffer.concat(chunks);
}

describe('extractTarball — happy path', () => {
  it('extracts files, strips the top-level package/ dir, and disposes', async () => {
    const tgz = await makeTgz([
      { name: 'package/index.js', content: 'console.log(1)' },
      { name: 'package/lib/util.js', content: 'export const x = 1;' },
    ]);
    const result = await extractTarball(tgz);

    expect(result.fileCount).toBe(2);
    expect(result.totalBytes).toBeGreaterThan(0);
    expect(readFileSync(join(result.extractedPath, 'index.js'), 'utf8')).toBe('console.log(1)');
    expect(existsSync(join(result.extractedPath, 'lib/util.js'))).toBe(true);

    await result.dispose();
    expect(existsSync(result.extractedPath)).toBe(false);
  });
});

describe('extractTarball — security guards', () => {
  it('rejects path-traversal (zip-slip) entries', async () => {
    const tgz = await makeTgz([
      { name: 'package/index.js', content: 'ok' },
      { name: 'package/../../../../tmp/evil.js', content: 'pwned' },
    ]);
    await expect(extractTarball(tgz)).rejects.toBeInstanceOf(TarballSecurityError);
  });

  it('skips symlink entries instead of writing them', async () => {
    const tgz = await makeTgz([
      { name: 'package/link', type: 'symlink', linkname: '/etc/passwd' },
      { name: 'package/ok.js', content: 'ok' },
    ]);
    const result = await extractTarball(tgz);
    try {
      expect(existsSync(join(result.extractedPath, 'link'))).toBe(false);
      expect(existsSync(join(result.extractedPath, 'ok.js'))).toBe(true);
      expect(result.skipped).toHaveLength(1);
      expect(result.skipped[0]?.reason).toMatch(/unsupported entry type/);
    } finally {
      await result.dispose();
    }
  });

  it('aborts when uncompressed size exceeds the limit (decompression bomb)', async () => {
    const tgz = await makeTgz([{ name: 'package/big.bin', content: 'A'.repeat(4096) }]);
    await expect(extractTarball(tgz, { maxTotalBytes: 1024 })).rejects.toBeInstanceOf(
      TarballSecurityError,
    );
  });

  it('aborts when the file count exceeds the limit', async () => {
    const entries: FixtureEntry[] = [];
    for (let i = 0; i < 5; i++) entries.push({ name: `package/f${i}.txt`, content: 'x' });
    await expect(
      extractTarball(await makeTgz(entries), { maxFileCount: 3 }),
    ).rejects.toBeInstanceOf(TarballSecurityError);
  });
});
