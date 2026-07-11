import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { UpdatePlanEntry } from '../types/update';
import { applyNpmUpdates } from './apply';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function entry(name: string, target: string): UpdatePlanEntry {
  return {
    current: { ecosystem: 'npm', name, version: '0.0.0' },
    targetVersion: target,
    tier: 'safe',
    fixesVulnerabilities: [],
    breaking: false,
    reason: 'test',
  };
}

describe('applyNpmUpdates', () => {
  it('bumps versions while preserving the range operator', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-fix-'));
    tmpDirs.push(dir);
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify(
        {
          name: 'demo',
          dependencies: { lodash: '^4.17.20', exact: '1.0.0' },
          devDependencies: { chalk: '~5.0.0' },
        },
        null,
        2,
      ),
    );

    const applied = await applyNpmUpdates(dir, [
      entry('lodash', '4.17.21'),
      entry('chalk', '5.0.2'),
      entry('exact', '1.0.1'),
    ]);

    const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8'));
    expect(pkg.dependencies.lodash).toBe('^4.17.21'); // caret preserved
    expect(pkg.devDependencies.chalk).toBe('~5.0.2'); // tilde preserved
    expect(pkg.dependencies.exact).toBe('1.0.1'); // exact preserved
    expect(applied).toHaveLength(3);
  });

  it('ignores non-npm entries and leaves the file untouched when nothing matches', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-fix-'));
    tmpDirs.push(dir);
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo', dependencies: {} }));
    const applied = await applyNpmUpdates(dir, [entry('not-here', '2.0.0')]);
    expect(applied).toEqual([]);
  });
});
