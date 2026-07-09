import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { packageKey, type DependencyNode } from '../types/index';
import { PypiAdapter } from './pypi-adapter';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function writeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-pypi-'));
  tmpDirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content);
  }
  return dir;
}

function byKey(nodes: DependencyNode[]): Map<string, DependencyNode> {
  return new Map(nodes.map((n) => [packageKey(n.ref), n]));
}

describe('PypiAdapter — poetry.lock', () => {
  it('builds a resolved graph with direct/transitive depth and dev scope', async () => {
    const dir = await writeProject({
      'pyproject.toml': [
        '[tool.poetry]',
        'name = "demo"',
        'version = "0.1.0"',
        '[tool.poetry.dependencies]',
        'python = "^3.11"',
        'flask = "^3.0"',
        '[tool.poetry.group.dev.dependencies]',
        'pytest = "^8.0"',
        '',
      ].join('\n'),
      'poetry.lock': [
        '[[package]]',
        'name = "flask"',
        'version = "3.0.0"',
        'groups = ["main"]',
        '[package.dependencies]',
        'werkzeug = ">=3.0"',
        '',
        '[[package]]',
        'name = "werkzeug"',
        'version = "3.0.1"',
        'groups = ["main"]',
        '',
        '[[package]]',
        'name = "pytest"',
        'version = "8.1.0"',
        'groups = ["dev"]',
        '',
      ].join('\n'),
    });

    const result = await new PypiAdapter().parseProject(dir);
    expect(result!.root).toMatchObject({ name: 'demo', version: '0.1.0' });

    const nodes = byKey(result!.nodes);
    expect(nodes.get('pypi:flask@3.0.0')).toMatchObject({ direct: true, depth: 1 });
    expect(nodes.get('pypi:flask@3.0.0')!.dependencies).toEqual(['pypi:werkzeug@3.0.1']);
    expect(nodes.get('pypi:werkzeug@3.0.1')).toMatchObject({ direct: false, depth: 2 });
    expect(nodes.get('pypi:pytest@8.1.0')).toMatchObject({
      direct: true,
      depth: 1,
      scopes: ['development'],
    });
  });
});

describe('PypiAdapter — requirements.txt', () => {
  it('parses pinned requirements as flat direct deps and skips unpinned/options', async () => {
    const dir = await writeProject({
      'requirements.txt': [
        '# project requirements',
        'Flask==3.0.0',
        'requests==2.31.0  # http',
        'django>=4.0',
        '-r other.txt',
        'uvicorn[standard]==0.29.0',
        '',
      ].join('\n'),
    });

    const result = await new PypiAdapter().parseProject(dir);
    const nodes = byKey(result!.nodes);
    expect([...nodes.keys()].sort()).toEqual([
      'pypi:flask@3.0.0',
      'pypi:requests@2.31.0',
      'pypi:uvicorn@0.29.0',
    ]);
    expect(nodes.get('pypi:flask@3.0.0')).toMatchObject({ direct: true, depth: 1 });
    // Unpinned (django) is intentionally excluded — no exact version to inventory.
    expect(nodes.has('pypi:django@4.0')).toBe(false);
  });
});

describe('PypiAdapter — absent', () => {
  it('returns null when no PyPI manifest is present', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-empty-'));
    tmpDirs.push(dir);
    expect(await new PypiAdapter().parseProject(dir)).toBeNull();
  });
});
