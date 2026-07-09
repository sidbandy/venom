import { describe, expect, it } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../../types/graph';
import { toSpdx } from './spdx';
import { toCycloneDx } from './cyclonedx';

function node(partial: Partial<DependencyNode> & Pick<DependencyNode, 'ref'>): DependencyNode {
  return {
    direct: false,
    depth: 2,
    scopes: ['production'],
    dependencies: [],
    parents: [],
    ...partial,
  };
}

function sampleGraph(): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  nodes.set(
    'npm:a@1.0.0',
    node({
      ref: { ecosystem: 'npm', name: 'a', version: '1.0.0' },
      direct: true,
      depth: 1,
      dependencies: ['npm:b@2.0.0'],
    }),
  );
  nodes.set(
    'npm:b@2.0.0',
    node({ ref: { ecosystem: 'npm', name: 'b', version: '2.0.0' }, parents: ['npm:a@1.0.0'] }),
  );
  nodes.set(
    'pypi:flask@3.0.0',
    node({ ref: { ecosystem: 'pypi', name: 'flask', version: '3.0.0' }, direct: true, depth: 1 }),
  );
  return {
    root: { name: 'demo', version: '1.0.0', path: '/tmp/demo' },
    ecosystems: ['npm', 'pypi'],
    nodes,
  };
}

const FIXED = {
  timestamp: '2026-07-08T00:00:00.000Z',
  documentId: 'fixed-id',
  toolVersion: '0.1.0',
};

describe('toSpdx', () => {
  it('produces a valid SPDX 2.3 skeleton with all packages', () => {
    const doc = toSpdx(sampleGraph(), FIXED);
    expect(doc.spdxVersion).toBe('SPDX-2.3');
    expect(doc.dataLicense).toBe('CC0-1.0');
    // root package + 3 dependencies
    expect(doc.packages).toHaveLength(4);
    const purls = doc.packages.flatMap((p) => p.externalRefs?.map((r) => r.referenceLocator) ?? []);
    expect(purls).toContain('pkg:npm/a@1.0.0');
    expect(purls).toContain('pkg:pypi/flask@3.0.0');
  });

  it('has referential integrity: every relationship references a declared element', () => {
    const doc = toSpdx(sampleGraph(), FIXED);
    const ids = new Set(['SPDXRef-DOCUMENT', ...doc.packages.map((p) => p.SPDXID)]);
    for (const rel of doc.relationships) {
      expect(ids.has(rel.spdxElementId)).toBe(true);
      expect(ids.has(rel.relatedSpdxElement)).toBe(true);
    }
    // The document must DESCRIBE the root package.
    expect(doc.relationships).toContainEqual({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-RootPackage',
    });
  });

  it('is deterministic for fixed options', () => {
    expect(toSpdx(sampleGraph(), FIXED)).toEqual(toSpdx(sampleGraph(), FIXED));
  });
});

describe('toCycloneDx', () => {
  it('produces a valid CycloneDX 1.5 skeleton with purl-keyed components', () => {
    const doc = toCycloneDx(sampleGraph(), FIXED);
    expect(doc.bomFormat).toBe('CycloneDX');
    expect(doc.specVersion).toBe('1.5');
    expect(doc.serialNumber).toBe('urn:uuid:fixed-id');
    expect(doc.components).toHaveLength(3);
    for (const c of doc.components) {
      expect(c.purl).toMatch(/^pkg:/);
      expect(c['bom-ref']).toBe(c.purl);
    }
  });

  it('has referential integrity: every dependency ref resolves to a component or root', () => {
    const doc = toCycloneDx(sampleGraph(), FIXED);
    const refs = new Set(['venom:root', ...doc.components.map((c) => c['bom-ref'])]);
    for (const dep of doc.dependencies) {
      expect(refs.has(dep.ref)).toBe(true);
      for (const on of dep.dependsOn) expect(refs.has(on)).toBe(true);
    }
    const root = doc.dependencies.find((d) => d.ref === 'venom:root')!;
    expect(root.dependsOn).toEqual(
      expect.arrayContaining(['pkg:npm/a@1.0.0', 'pkg:pypi/flask@3.0.0']),
    );
  });

  it('is deterministic for fixed options', () => {
    expect(toCycloneDx(sampleGraph(), FIXED)).toEqual(toCycloneDx(sampleGraph(), FIXED));
  });
});
