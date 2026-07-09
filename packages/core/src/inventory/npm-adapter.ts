import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { ScanContext } from '../types/context';
import type { PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { FetchedTarball, RegistryMetadata } from '../types/registry';
import { toPurl } from './purl';

/** A mutable node used while resolving; converted to a {@link DependencyNode} at the end. */
interface WorkingNode {
  ref: PackageRef;
  direct: boolean;
  depth: number;
  scopes: Set<DependencyScope>;
  dependencies: Set<string>;
  parents: Set<string>;
}

/** Shape of a package entry in a lockfileVersion 2/3 `packages` map. */
interface LockPackageEntry {
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/** Shape of a dependency entry in a legacy lockfileVersion 1 `dependencies` tree. */
interface LegacyDepEntry {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, LegacyDepEntry>;
}

interface NpmLockfile {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  packages?: Record<string, LockPackageEntry>;
  dependencies?: Record<string, LegacyDepEntry>;
}

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

const NODE_MODULES = 'node_modules/';

/**
 * npm ecosystem adapter (SPEC.md §4 M1). Parses `package-lock.json` /
 * `npm-shrinkwrap.json` into a fully-resolved set of dependency nodes with
 * accurate parent/child edges and shortest-path depth. Supports the modern
 * `packages` map (lockfileVersion 2 & 3, npm 7+) precisely, with a best-effort
 * path for the legacy nested `dependencies` tree (lockfileVersion 1).
 */
export class NpmAdapter implements EcosystemAdapter {
  readonly ecosystem = 'npm' as const;

  async parseProject(projectRoot: string): Promise<EcosystemParseResult | null> {
    const lock = await this.#readLockfile(projectRoot);
    if (!lock) return null;

    const pkgJson = await this.#readJson<PackageJson>(join(projectRoot, 'package.json'));
    const root: ProjectRoot = {
      name: pkgJson?.name ?? lock.name ?? basename(projectRoot),
      ...((pkgJson?.version ?? lock.version) ? { version: pkgJson?.version ?? lock.version } : {}),
      path: projectRoot,
    };

    const usePackagesMap = lock.packages && Object.keys(lock.packages).length > 0;
    const nodes = usePackagesMap
      ? this.#parsePackagesMap(lock.packages as Record<string, LockPackageEntry>, pkgJson)
      : this.#parseLegacyTree(lock, pkgJson);

    return { root, nodes };
  }

  purl(ref: PackageRef): string {
    return toPurl(ref);
  }

  // The following are implemented in Module 3 (malicious detection); inventory
  // (Module 1) does not need them.
  async fetchMetadata(_ref: PackageRef, _ctx: ScanContext): Promise<RegistryMetadata | null> {
    return null;
  }
  async fetchTarball(_ref: PackageRef, _ctx: ScanContext): Promise<FetchedTarball | null> {
    return null;
  }
  async popularNames(_ctx: ScanContext): Promise<string[]> {
    return [];
  }

  async #readLockfile(projectRoot: string): Promise<NpmLockfile | null> {
    for (const file of ['package-lock.json', 'npm-shrinkwrap.json']) {
      const lock = await this.#readJson<NpmLockfile>(join(projectRoot, file));
      if (lock) return lock;
    }
    return null;
  }

  async #readJson<T>(path: string): Promise<T | null> {
    try {
      return JSON.parse(await readFile(path, 'utf8')) as T;
    } catch {
      return null;
    }
  }

  /** Parse a lockfileVersion 2/3 `packages` map with real node_modules resolution. */
  #parsePackagesMap(
    packages: Record<string, LockPackageEntry>,
    pkgJson: PackageJson | null,
  ): DependencyNode[] {
    const working = new Map<string, WorkingNode>();

    const getNode = (ref: PackageRef): WorkingNode => {
      const key = packageKey(ref);
      let node = working.get(key);
      if (!node) {
        node = {
          ref,
          direct: false,
          depth: Number.POSITIVE_INFINITY,
          scopes: new Set(),
          dependencies: new Set(),
          parents: new Set(),
        };
        working.set(key, node);
      }
      return node;
    };

    const refForKey = (key: string): PackageRef | null => {
      const entry = packages[key];
      if (!entry || entry.link || !entry.version) return null;
      return { ecosystem: 'npm', name: nameFromKey(key), version: entry.version };
    };

    // 1. Create a node per installed third-party instance and record its scope.
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '' || entry.link || !key.startsWith(NODE_MODULES) || !entry.version) continue;
      const ref = refForKey(key);
      if (!ref) continue;
      const node = getNode(ref);
      node.scopes.add(instanceScope(entry));
    }

    // 2. Resolve edges by walking node_modules the way npm does.
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '' || entry.link || !entry.version) continue;
      const parentRef = refForKey(key);
      if (!parentRef) continue;
      const parentKey = packageKey(parentRef);
      const declared = { ...entry.dependencies, ...entry.optionalDependencies };
      for (const depName of Object.keys(declared)) {
        const resolvedKey = resolveInstanceKey(key, depName, packages);
        if (!resolvedKey) continue;
        const childRef = refForKey(resolvedKey);
        if (!childRef) continue;
        const childKey = packageKey(childRef);
        if (childKey === parentKey) continue;
        working.get(parentKey)?.dependencies.add(childKey);
        getNode(childRef).parents.add(parentKey);
      }
    }

    // 3. Mark direct dependencies (from the manifest) and seed the depth BFS.
    const rootEntry = packages[''];
    const directScopes = directDependencyScopes(pkgJson, rootEntry);
    const seeds: string[] = [];
    for (const [name, scope] of directScopes) {
      const resolvedKey = resolveInstanceKey('', name, packages);
      if (!resolvedKey) continue;
      const ref = refForKey(resolvedKey);
      if (!ref) continue;
      const node = getNode(ref);
      node.direct = true;
      node.depth = 1;
      node.scopes.add(scope);
      seeds.push(packageKey(ref));
    }

    assignDepth(working, seeds);
    return finalizeNodes(working);
  }

  /**
   * Best-effort parse of a legacy lockfileVersion 1 nested `dependencies` tree.
   * Direct dependencies come from the manifest (the lockfile's top level is a
   * hoisted flat list, not the direct set); edges are approximated from
   * `requires`. Modern npm (7+) emits lockfileVersion 2/3, handled above.
   */
  #parseLegacyTree(lock: NpmLockfile, pkgJson: PackageJson | null): DependencyNode[] {
    const working = new Map<string, WorkingNode>();
    // Resolve each name to a version, preferring the shallowest (top-level) install.
    const versionOf = new Map<string, string>();
    const collectVersions = (deps: Record<string, LegacyDepEntry> | undefined): void => {
      if (!deps) return;
      for (const [name, entry] of Object.entries(deps)) {
        if (entry.version && !versionOf.has(name)) versionOf.set(name, entry.version);
        collectVersions(entry.dependencies);
      }
    };
    collectVersions(lock.dependencies);

    const getNode = (name: string): WorkingNode | null => {
      const version = versionOf.get(name);
      if (!version) return null;
      const ref: PackageRef = { ecosystem: 'npm', name, version };
      const key = packageKey(ref);
      let node = working.get(key);
      if (!node) {
        node = {
          ref,
          direct: false,
          depth: Number.POSITIVE_INFINITY,
          scopes: new Set(),
          dependencies: new Set(),
          parents: new Set(),
        };
        working.set(key, node);
      }
      return node;
    };

    const walk = (deps: Record<string, LegacyDepEntry> | undefined): void => {
      if (!deps) return;
      for (const [name, entry] of Object.entries(deps)) {
        const node = getNode(name);
        if (node) {
          node.scopes.add(entry.dev ? 'development' : entry.optional ? 'optional' : 'production');
          for (const reqName of Object.keys(entry.requires ?? {})) {
            const child = getNode(reqName);
            if (child && packageKey(child.ref) !== packageKey(node.ref)) {
              node.dependencies.add(packageKey(child.ref));
              child.parents.add(packageKey(node.ref));
            }
          }
        }
        walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);

    const directScopes = directDependencyScopes(pkgJson, undefined);
    const seeds: string[] = [];
    for (const [name, scope] of directScopes) {
      const node = getNode(name);
      if (!node) continue;
      node.direct = true;
      node.depth = 1;
      node.scopes.add(scope);
      seeds.push(packageKey(node.ref));
    }

    assignDepth(working, seeds);
    return finalizeNodes(working);
  }
}

/** The package name encoded in a `packages`-map key (handles scoped names). */
function nameFromKey(key: string): string {
  const idx = key.lastIndexOf(NODE_MODULES);
  return idx === -1 ? key : key.slice(idx + NODE_MODULES.length);
}

/** Resolve a dependency name from a package's install path, walking up node_modules. */
function resolveInstanceKey(
  fromPath: string,
  name: string,
  packages: Record<string, LockPackageEntry>,
): string | undefined {
  let base = fromPath;
  for (;;) {
    const prefix = base === '' ? '' : `${base}/`;
    const candidate = `${prefix}${NODE_MODULES}${name}`;
    if (Object.prototype.hasOwnProperty.call(packages, candidate)) return candidate;
    if (base === '') return undefined;
    const idx = base.lastIndexOf(`/${NODE_MODULES}`);
    base = idx === -1 ? '' : base.slice(0, idx);
  }
}

function instanceScope(entry: LockPackageEntry): DependencyScope {
  if (entry.dev) return 'development';
  if (entry.optional) return 'optional';
  return 'production';
}

/** Direct dependency names → scope, from the manifest (preferred) or the root lock entry. */
function directDependencyScopes(
  pkgJson: PackageJson | null,
  rootEntry: LockPackageEntry | undefined,
): Map<string, DependencyScope> {
  const source = pkgJson ?? rootEntry ?? {};
  const result = new Map<string, DependencyScope>();
  // Precedence: production > optional > peer > development.
  for (const name of Object.keys(source.devDependencies ?? {})) result.set(name, 'development');
  for (const name of Object.keys(source.peerDependencies ?? {})) result.set(name, 'peer');
  for (const name of Object.keys(source.optionalDependencies ?? {})) result.set(name, 'optional');
  for (const name of Object.keys(source.dependencies ?? {})) result.set(name, 'production');
  return result;
}

/** Shortest-path depth from the direct dependencies (BFS over prod/optional edges). */
function assignDepth(working: Map<string, WorkingNode>, seeds: string[]): void {
  const queue: string[] = [...seeds];
  let head = 0;
  while (head < queue.length) {
    const key = queue[head++]!;
    const node = working.get(key);
    if (!node) continue;
    for (const childKey of node.dependencies) {
      const child = working.get(childKey);
      if (!child) continue;
      if (child.depth > node.depth + 1) {
        child.depth = node.depth + 1;
        queue.push(childKey);
      }
    }
  }
  // Any node never reached (e.g. an orphaned optional install) gets a best-effort depth.
  for (const node of working.values()) {
    if (!Number.isFinite(node.depth)) node.depth = node.direct ? 1 : 2;
  }
}

/** Freeze working nodes into immutable DependencyNodes with deterministic ordering. */
function finalizeNodes(working: Map<string, WorkingNode>): DependencyNode[] {
  return [...working.values()]
    .map((n) => ({
      ref: n.ref,
      direct: n.direct,
      depth: n.depth,
      scopes: [...n.scopes].sort(),
      dependencies: [...n.dependencies].sort(),
      parents: [...n.parents].sort(),
    }))
    .sort((a, b) => packageKey(a.ref).localeCompare(packageKey(b.ref)));
}
