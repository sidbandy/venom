import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../types/graph';
import { detectUnusedDependencies } from './unused-deps';
import { checkLicenses } from './licenses';
import { checkSecretsHygiene } from './secrets-hygiene';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tmp(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-analysis-'));
  tmpDirs.push(dir);
  return dir;
}

async function write(dir: string, rel: string, content: string): Promise<void> {
  const full = join(dir, rel);
  await mkdir(join(full, '..'), { recursive: true });
  await writeFile(full, content);
}

function npmNode(name: string, version = '1.0.0'): DependencyNode {
  return {
    ref: { ecosystem: 'npm', name, version },
    direct: true,
    depth: 1,
    scopes: ['production'],
    dependencies: [],
    parents: [],
  };
}

function graphOf(...names: string[]): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  for (const n of names) nodes.set(`npm:${n}@1.0.0`, npmNode(n));
  return { root: { name: 'demo', version: '1.0.0', path: '/x' }, ecosystems: ['npm'], nodes };
}

describe('detectUnusedDependencies', () => {
  it('flags declared production deps never imported, ignoring @types', async () => {
    const dir = await tmp();
    await write(
      dir,
      'package.json',
      JSON.stringify({ dependencies: { used: '1', unusedpkg: '1', '@types/node': '1' } }),
    );
    await write(dir, 'src/index.ts', "import { thing } from 'used';\nconsole.log(thing);\n");

    const { unused } = await detectUnusedDependencies(dir);
    expect(unused).toEqual(['unusedpkg']);
  });
});

describe('checkLicenses', () => {
  it('flags denylisted and copyleft licenses and installed packages with none', async () => {
    const dir = await tmp();
    await write(dir, 'node_modules/mit-pkg/package.json', JSON.stringify({ license: 'MIT' }));
    await write(dir, 'node_modules/agpl-pkg/package.json', JSON.stringify({ license: 'AGPL-3.0' }));
    await write(dir, 'node_modules/gpl-pkg/package.json', JSON.stringify({ license: 'GPL-3.0' }));
    await write(
      dir,
      'node_modules/nolicense-pkg/package.json',
      JSON.stringify({ name: 'nolicense-pkg' }),
    );

    const { findings, byLicense } = await checkLicenses(
      dir,
      graphOf('mit-pkg', 'agpl-pkg', 'gpl-pkg', 'nolicense-pkg', 'not-installed-pkg'),
      { projectLicense: 'MIT' },
    );

    expect(byLicense['MIT']).toBe(1);
    const rules = findings.map((f) => f.ruleId);
    expect(rules).toContain('venom/license-denylist'); // AGPL
    expect(rules).toContain('venom/license-conflict'); // GPL vs MIT project
    expect(rules).toContain('venom/license-unknown'); // installed, no license
    // A package absent from node_modules is not reported at all.
    expect(findings.some((f) => f.message.includes('not-installed-pkg'))).toBe(false);
  });
});

describe('checkSecretsHygiene', () => {
  it('warns when .gitignore is missing', async () => {
    const dir = await tmp();
    const { findings } = await checkSecretsHygiene(dir);
    expect(
      findings.some((f) => f.ruleId === 'venom/hygiene-gitignore' && f.level === 'warning'),
    ).toBe(true);
  });

  it('flags a .env with no .env.example and gaps in .gitignore', async () => {
    const dir = await tmp();
    await write(dir, '.gitignore', 'node_modules/\n.env\n');
    await write(dir, '.env', 'SECRET=1\n');
    const { findings } = await checkSecretsHygiene(dir);
    expect(findings.some((f) => f.ruleId === 'venom/hygiene-env-example')).toBe(true);
    // .env is covered, but *.pem / *.key / credentials.json are not.
    expect(findings.some((f) => f.title.includes('*.pem'))).toBe(true);
  });

  it('is quiet for a well-configured project', async () => {
    const dir = await tmp();
    await write(dir, '.gitignore', '.env\n*.pem\n*.key\ncredentials.json\n');
    const { findings } = await checkSecretsHygiene(dir);
    expect(findings).toEqual([]);
  });
});
