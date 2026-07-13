import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../types/graph';
import { computeReachablePackages } from './reachability';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function node(name: string, opts: Partial<DependencyNode> = {}): DependencyNode {
  return {
    ref: { ecosystem: 'npm', name, version: '1.0.0' },
    direct: false,
    depth: 1,
    scopes: ['production'],
    dependencies: [],
    parents: [],
    ...opts,
  };
}

describe('computeReachablePackages', () => {
  it('reaches only what the source imports, transitively through the graph', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-reach-'));
    tmpDirs.push(dir);
    await mkdir(join(dir, 'src'), { recursive: true });
    // The project imports only `a` — not `b`.
    await writeFile(join(dir, 'src/index.js'), "const a = require('a');\nconsole.log(a);\n");

    const nodes = new Map<string, DependencyNode>();
    // a (direct, imported) → c ;  b (direct, NOT imported) → d
    nodes.set('npm:a@1.0.0', node('a', { direct: true, dependencies: ['npm:c@1.0.0'] }));
    nodes.set('npm:b@1.0.0', node('b', { direct: true, dependencies: ['npm:d@1.0.0'] }));
    nodes.set('npm:c@1.0.0', node('c', { parents: ['npm:a@1.0.0'] }));
    nodes.set('npm:d@1.0.0', node('d', { parents: ['npm:b@1.0.0'] }));
    const graph: DependencyGraph = {
      root: { name: 'demo', version: '1.0.0', path: dir },
      ecosystems: ['npm'],
      nodes,
    };

    const reachable = await computeReachablePackages(dir, graph);
    expect(reachable.has('npm:a@1.0.0')).toBe(true); // imported
    expect(reachable.has('npm:c@1.0.0')).toBe(true); // dep of an imported package
    expect(reachable.has('npm:b@1.0.0')).toBe(false); // declared but never imported
    expect(reachable.has('npm:d@1.0.0')).toBe(false); // only reachable via b
  });

  it('returns an empty set when there is no analyzable source (reachability unknown)', async () => {
    // A project with no JS/TS source (e.g. a pure-Python project) yields no
    // reachable packages. auditProject treats this empty set as "reachability
    // unknown" and must NOT down-weight CVEs — asserted here as the boundary
    // condition that the audit gate (`reachabilityAnalyzed`) depends on.
    const dir = await mkdtemp(join(tmpdir(), 'venom-reach-empty-'));
    tmpDirs.push(dir);

    const nodes = new Map<string, DependencyNode>();
    nodes.set('npm:a@1.0.0', node('a', { direct: true }));
    const graph: DependencyGraph = {
      root: { name: 'demo', version: '1.0.0', path: dir },
      ecosystems: ['npm'],
      nodes,
    };

    const reachable = await computeReachablePackages(dir, graph);
    expect(reachable.size).toBe(0);
  });
});
