import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { packageKey, type DependencyNode } from '../types/index';
import { NpmAdapter } from './npm-adapter';

const tmpDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

/** Write a throwaway npm project (package.json + package-lock.json) to a temp dir. */
async function writeProject(files: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-npm-'));
  tmpDirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), JSON.stringify(content, null, 2));
  }
  return dir;
}

function byKey(nodes: DependencyNode[]): Map<string, DependencyNode> {
  return new Map(nodes.map((n) => [packageKey(n.ref), n]));
}

describe('NpmAdapter — lockfileVersion 3 (packages map)', () => {
  it('resolves versions, direct/transitive depth, scopes, and edges', async () => {
    const dir = await writeProject({
      'package.json': {
        name: 'demo',
        version: '1.0.0',
        dependencies: { a: '^1.0.0' },
        devDependencies: { d: '^2.0.0' },
      },
      'package-lock.json': {
        name: 'demo',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'demo',
            version: '1.0.0',
            dependencies: { a: '^1.0.0' },
            devDependencies: { d: '^2.0.0' },
          },
          'node_modules/a': { version: '1.2.0', dependencies: { b: '^3.0.0' } },
          'node_modules/b': { version: '3.1.0' },
          'node_modules/d': { version: '2.0.1', dev: true },
        },
      },
    });

    const result = await new NpmAdapter().parseProject(dir);
    expect(result).not.toBeNull();
    expect(result!.root).toMatchObject({ name: 'demo', version: '1.0.0' });

    const nodes = byKey(result!.nodes);
    const a = nodes.get('npm:a@1.2.0')!;
    const b = nodes.get('npm:b@3.1.0')!;
    const d = nodes.get('npm:d@2.0.1')!;

    expect(a).toMatchObject({ direct: true, depth: 1, scopes: ['production'] });
    expect(a.dependencies).toEqual(['npm:b@3.1.0']);
    expect(b).toMatchObject({ direct: false, depth: 2, scopes: ['production'] });
    expect(b.parents).toEqual(['npm:a@1.2.0']);
    expect(d).toMatchObject({ direct: true, depth: 1, scopes: ['development'] });
  });

  it('resolves scoped packages nested under a parent', async () => {
    const dir = await writeProject({
      'package.json': { name: 'demo', version: '1.0.0', dependencies: { a: '^1.0.0' } },
      'package-lock.json': {
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo', version: '1.0.0', dependencies: { a: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { '@scope/util': '^1.0.0' } },
          'node_modules/@scope/util': { version: '1.4.2' },
        },
      },
    });

    const nodes = byKey((await new NpmAdapter().parseProject(dir))!.nodes);
    const util = nodes.get('npm:@scope/util@1.4.2')!;
    expect(util).toBeDefined();
    expect(util.depth).toBe(2);
    expect(nodes.get('npm:a@1.0.0')!.dependencies).toContain('npm:@scope/util@1.4.2');
  });

  it('prefers a nested install over a hoisted one during resolution', async () => {
    // `a` and `b` both depend on `c`, but at different versions: a nested copy of
    // c@2 lives under b, while c@1 is hoisted to the top.
    const dir = await writeProject({
      'package.json': { name: 'demo', version: '1.0.0', dependencies: { a: '^1', b: '^1' } },
      'package-lock.json': {
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo', version: '1.0.0', dependencies: { a: '^1', b: '^1' } },
          'node_modules/a': { version: '1.0.0', dependencies: { c: '^1' } },
          'node_modules/b': { version: '1.0.0', dependencies: { c: '^2' } },
          'node_modules/c': { version: '1.0.0' },
          'node_modules/b/node_modules/c': { version: '2.0.0' },
        },
      },
    });

    const nodes = byKey((await new NpmAdapter().parseProject(dir))!.nodes);
    expect(nodes.get('npm:a@1.0.0')!.dependencies).toEqual(['npm:c@1.0.0']);
    expect(nodes.get('npm:b@1.0.0')!.dependencies).toEqual(['npm:c@2.0.0']);
    expect(nodes.has('npm:c@1.0.0')).toBe(true);
    expect(nodes.has('npm:c@2.0.0')).toBe(true);
  });
});

describe('NpmAdapter — lockfileVersion 1 (legacy tree)', () => {
  it('parses nested dependencies with requires edges', async () => {
    const dir = await writeProject({
      'package.json': { name: 'legacy', version: '0.0.1', dependencies: { a: '^1.0.0' } },
      'package-lock.json': {
        name: 'legacy',
        version: '0.0.1',
        lockfileVersion: 1,
        dependencies: {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } },
          b: { version: '1.5.0' },
        },
      },
    });

    const nodes = byKey((await new NpmAdapter().parseProject(dir))!.nodes);
    expect(nodes.get('npm:a@1.0.0')).toMatchObject({ direct: true, depth: 1 });
    expect(nodes.get('npm:a@1.0.0')!.dependencies).toEqual(['npm:b@1.5.0']);
    expect(nodes.get('npm:b@1.5.0')).toMatchObject({ direct: false, depth: 2 });
  });
});

describe('NpmAdapter — absent', () => {
  it('returns null when there is no npm lockfile', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-empty-'));
    tmpDirs.push(dir);
    expect(await new NpmAdapter().parseProject(dir)).toBeNull();
  });
});
