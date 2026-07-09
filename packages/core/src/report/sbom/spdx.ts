import { randomUUID } from 'node:crypto';
import { packageKey } from '../../types/ecosystem';
import type { DependencyGraph, DependencyNode } from '../../types/graph';
import { toPurl } from '../../inventory/purl';
import type { SbomOptions } from './types';

const NOASSERTION = 'NOASSERTION';

export interface SpdxDocument {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: { created: string; creators: string[] };
  packages: SpdxPackage[];
  relationships: SpdxRelationship[];
}

interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation: string;
  filesAnalyzed: false;
  licenseConcluded: string;
  licenseDeclared: string;
  externalRefs?: Array<{
    referenceCategory: 'PACKAGE-MANAGER';
    referenceType: 'purl';
    referenceLocator: string;
  }>;
}

interface SpdxRelationship {
  spdxElementId: string;
  relationshipType: 'DESCRIBES' | 'DEPENDS_ON';
  relatedSpdxElement: string;
}

const ROOT_SPDXID = 'SPDXRef-RootPackage';

/**
 * Emit an SPDX 2.3 SBOM (SPEC.md §4 M1, §12) — the format government and
 * enterprise compliance teams expect. Output is deterministic given a fixed
 * `documentId`/`timestamp`: packages are sorted by package key and assigned
 * stable SPDXIDs, so two runs over the same graph diff cleanly.
 */
export function toSpdx(graph: DependencyGraph, options: SbomOptions = {}): SpdxDocument {
  const created = options.timestamp ?? new Date().toISOString();
  const documentId = options.documentId ?? randomUUID();
  const toolVersion = options.toolVersion ?? '0.1.0';

  const sorted = [...graph.nodes.values()].sort((a, b) =>
    packageKey(a.ref).localeCompare(packageKey(b.ref)),
  );

  // Assign a stable SPDXID per package, in sorted order.
  const idByKey = new Map<string, string>();
  sorted.forEach((node, i) => idByKey.set(packageKey(node.ref), `SPDXRef-Package-${i}`));

  const packages: SpdxPackage[] = [
    {
      SPDXID: ROOT_SPDXID,
      name: graph.root.name,
      ...(graph.root.version ? { versionInfo: graph.root.version } : {}),
      downloadLocation: NOASSERTION,
      filesAnalyzed: false,
      licenseConcluded: NOASSERTION,
      licenseDeclared: NOASSERTION,
    },
    ...sorted.map((node) => spdxPackage(node, idByKey.get(packageKey(node.ref))!)),
  ];

  const relationships: SpdxRelationship[] = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: ROOT_SPDXID,
    },
  ];
  for (const node of sorted) {
    const nodeId = idByKey.get(packageKey(node.ref))!;
    // The root project depends on each of its direct dependencies.
    if (node.direct) {
      relationships.push({
        spdxElementId: ROOT_SPDXID,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: nodeId,
      });
    }
    // Each package depends on its own resolved children.
    for (const childKey of node.dependencies) {
      const childId = idByKey.get(childKey);
      if (!childId) continue;
      relationships.push({
        spdxElementId: nodeId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: childId,
      });
    }
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${graph.root.name} SBOM`,
    documentNamespace: `https://venom.dev/spdx/${encodeURIComponent(graph.root.name)}-${documentId}`,
    creationInfo: { created, creators: [`Tool: venom-${toolVersion}`] },
    packages,
    relationships,
  };
}

function spdxPackage(node: DependencyNode, spdxId: string): SpdxPackage {
  return {
    SPDXID: spdxId,
    name: node.ref.name,
    versionInfo: node.ref.version,
    downloadLocation: NOASSERTION,
    filesAnalyzed: false,
    licenseConcluded: NOASSERTION,
    licenseDeclared: NOASSERTION,
    externalRefs: [
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: toPurl(node.ref),
      },
    ],
  };
}
