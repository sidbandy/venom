import { parse as parseYaml } from 'yaml';
import type { PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import { assignDepth, finalizeNodes, getOrCreateNode, type WorkingNode } from './working-graph';

type PnpmDepSpec = string | { version?: string; specifier?: string };

interface PnpmImporter {
  dependencies?: Record<string, PnpmDepSpec>;
  devDependencies?: Record<string, PnpmDepSpec>;
  optionalDependencies?: Record<string, PnpmDepSpec>;
}

interface PnpmEdges {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PnpmDoc extends PnpmImporter {
  importers?: Record<string, PnpmImporter>;
  packages?: Record<string, PnpmEdges>;
  snapshots?: Record<string, PnpmEdges>;
}

/**
 * Parse `pnpm-lock.yaml` (lockfileVersion 6 and 9) into resolved dependency nodes.
 * v6 keys packages as `/name@version` with edges inline; v9 keys as `name@version`
 * and puts edges under `snapshots`. Both feed the same npm dependency graph.
 */
export function parsePnpmLock(content: string, root: ProjectRoot): DependencyNode[] {
  const doc = parseYaml(content) as PnpmDoc;
  const importer: PnpmImporter = doc.importers?.['.'] ?? {
    ...(doc.dependencies ? { dependencies: doc.dependencies } : {}),
    ...(doc.devDependencies ? { devDependencies: doc.devDependencies } : {}),
    ...(doc.optionalDependencies ? { optionalDependencies: doc.optionalDependencies } : {}),
  };
  const packages = doc.packages ?? {};
  const edges = doc.snapshots ?? doc.packages ?? {};

  const working = new Map<string, WorkingNode>();

  // A node per resolved package.
  for (const rawKey of Object.keys(packages)) {
    const ref = refFromPnpmKey(rawKey);
    if (ref) getOrCreateNode(working, ref);
  }

  // Resolved edges.
  for (const [rawKey, snap] of Object.entries(edges)) {
    const parentRef = refFromPnpmKey(rawKey);
    if (!parentRef) continue;
    const parentKey = packageKey(parentRef);
    const parent = working.get(parentKey);
    if (!parent) continue;
    const deps = { ...snap?.dependencies, ...snap?.optionalDependencies };
    for (const [depName, depVersion] of Object.entries(deps)) {
      const childRef: PackageRef = {
        ecosystem: 'npm',
        name: depName,
        version: stripQualifiers(String(depVersion)),
      };
      const childKey = packageKey(childRef);
      const child = working.get(childKey);
      if (child) {
        parent.dependencies.add(childKey);
        child.parents.add(parentKey);
      }
    }
  }

  // Direct dependencies (from the workspace importer).
  const seeds: string[] = [];
  const sections: Array<[Record<string, PnpmDepSpec> | undefined, DependencyScope]> = [
    [importer.devDependencies, 'development'],
    [importer.optionalDependencies, 'optional'],
    [importer.dependencies, 'production'],
  ];
  for (const [specs, scope] of sections) {
    for (const [name, spec] of Object.entries(specs ?? {})) {
      const version = stripQualifiers(specVersion(spec));
      if (!version) continue;
      const node = getOrCreateNode(working, { ecosystem: 'npm', name, version });
      node.direct = true;
      node.depth = 1;
      node.scopes.add(scope);
      seeds.push(packageKey(node.ref));
    }
  }

  assignDepth(working, seeds);
  void root;
  return finalizeNodes(working);
}

/** `/@scope/name@1.0.0(peer@2)` → `{ '@scope/name', '1.0.0' }`. */
function refFromPnpmKey(rawKey: string): PackageRef | null {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  const paren = key.indexOf('(');
  if (paren !== -1) key = key.slice(0, paren);
  const at = key.lastIndexOf('@');
  if (at <= 0) return null;
  const name = key.slice(0, at);
  const version = key.slice(at + 1);
  if (!name || !version) return null;
  return { ecosystem: 'npm', name, version };
}

function specVersion(spec: PnpmDepSpec): string {
  return typeof spec === 'string' ? spec : (spec.version ?? '');
}

/** Strip a leading `/` and any `(peer)` qualifier from a version string. */
function stripQualifiers(version: string): string {
  const noSlash = version.startsWith('/') ? version.slice(1) : version;
  const paren = noSlash.indexOf('(');
  return paren === -1 ? noSlash : noSlash.slice(0, paren);
}
