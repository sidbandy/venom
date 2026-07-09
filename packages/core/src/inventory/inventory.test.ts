import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { inventoryProject, NoSupportedLockfileError } from './inventory';
import { summarizeGraph } from './build-graph';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function writeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-inv-'));
  tmpDirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content);
  }
  return dir;
}

describe('inventoryProject', () => {
  it('merges npm + PyPI manifests into one cross-ecosystem graph', async () => {
    const dir = await writeProject({
      'package.json': JSON.stringify({
        name: 'poly',
        version: '1.0.0',
        dependencies: { a: '^1.0.0' },
      }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'poly', version: '1.0.0', dependencies: { a: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0' },
        },
      }),
      'requirements.txt': 'flask==3.0.0\n',
    });

    const graph = await inventoryProject(dir);
    const summary = summarizeGraph(graph);

    expect(summary.ecosystems).toEqual(['npm', 'pypi']);
    expect(graph.nodes.has('npm:a@1.0.0')).toBe(true);
    expect(graph.nodes.has('pypi:flask@3.0.0')).toBe(true);
    expect(summary.total).toBe(2);
    expect(summary.byEcosystem).toEqual({ npm: 1, pypi: 1 });
  });

  it('throws NoSupportedLockfileError for a project with no lockfile', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-none-'));
    tmpDirs.push(dir);
    await expect(inventoryProject(dir)).rejects.toBeInstanceOf(NoSupportedLockfileError);
  });
});
