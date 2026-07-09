import { randomUUID } from 'node:crypto';
import { packageKey } from '../../types/ecosystem';
import type { DependencyGraph, DependencyNode } from '../../types/graph';
import { toPurl } from '../../inventory/purl';
import type { SbomOptions } from './types';

const ROOT_REF = 'venom:root';

export interface CycloneDxDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component: { type: 'application'; 'bom-ref': string; name: string; version?: string };
  };
  components: CycloneDxComponent[];
  dependencies: CycloneDxDependency[];
}

interface CycloneDxComponent {
  type: 'library';
  'bom-ref': string;
  name: string;
  version: string;
  purl: string;
  scope: 'required' | 'optional';
}

interface CycloneDxDependency {
  ref: string;
  dependsOn: string[];
}

/**
 * Emit a CycloneDX 1.5 SBOM (SPEC.md §4 M1, §12) — the format the security
 * tooling ecosystem (Dependency-Track, SCA scanners) consumes. Deterministic
 * given a fixed `documentId`/`timestamp`; `bom-ref`s are purls, so the dependency
 * graph is expressed with stable, globally-unique identifiers.
 */
export function toCycloneDx(graph: DependencyGraph, options: SbomOptions = {}): CycloneDxDocument {
  const timestamp = options.timestamp ?? new Date().toISOString();
  const serial = options.documentId ?? randomUUID();
  const toolVersion = options.toolVersion ?? '0.1.0';

  const sorted = [...graph.nodes.values()].sort((a, b) =>
    packageKey(a.ref).localeCompare(packageKey(b.ref)),
  );

  const components: CycloneDxComponent[] = sorted.map(componentFor);

  // Dependency edges: root → direct deps, and each package → its children.
  const dependencies: CycloneDxDependency[] = [];
  const directRefs = sorted.filter((n) => n.direct).map((n) => toPurl(n.ref));
  dependencies.push({ ref: ROOT_REF, dependsOn: directRefs });
  for (const node of sorted) {
    const dependsOn = node.dependencies
      .map((childKey) => graph.nodes.get(childKey))
      .filter((child): child is DependencyNode => child !== undefined)
      .map((child) => toPurl(child.ref));
    dependencies.push({ ref: toPurl(node.ref), dependsOn });
  }

  const rootComponent = {
    type: 'application' as const,
    'bom-ref': ROOT_REF,
    name: graph.root.name,
    ...(graph.root.version ? { version: graph.root.version } : {}),
  };

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${serial}`,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'Venom', name: 'venom', version: toolVersion }],
      component: rootComponent,
    },
    components,
    dependencies,
  };
}

function componentFor(node: DependencyNode): CycloneDxComponent {
  const purl = toPurl(node.ref);
  const isProd = node.scopes.includes('production');
  return {
    type: 'library',
    'bom-ref': purl,
    name: node.ref.name,
    version: node.ref.version,
    purl,
    scope: isProd ? 'required' : 'optional',
  };
}
