import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { ScanContext } from '../types/context';
import type { PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { FetchedTarball, RegistryMetadata } from '../types/registry';
import { extractTarball } from '../extract/tarball';
import { INSTALL_LIFECYCLE } from '../malicious/install-scripts';
import { popularNamesFor } from '../malicious/popular-names';
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

type LicenseField = string | { type?: string } | undefined;

interface PackumentVersion {
  version: string;
  dist?: { tarball?: string; integrity?: string };
  scripts?: Record<string, string>;
  license?: LicenseField;
  deprecated?: string;
}

interface Packument {
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, PackumentVersion>;
  time?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
  license?: LicenseField;
  repository?: { url?: string } | string;
  homepage?: string;
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

  async fetchMetadata(ref: PackageRef, ctx: ScanContext): Promise<RegistryMetadata | null> {
    const doc = await this.#packument(ref.name, ctx);
    if (!doc) return null;

    const version = this.#resolveVersion(doc, ref.version);
    const versionInfo = version ? doc.versions?.[version] : undefined;
    const scripts = filterLifecycle(versionInfo?.scripts);
    const license = licenseString(versionInfo?.license ?? doc.license);
    const repoUrl = repositoryUrl(doc.repository);
    const publishedAt = version ? doc.time?.[version] : undefined;

    const meta: RegistryMetadata = {
      ref: { ...ref, version: version ?? ref.version },
      maintainers: (doc.maintainers ?? []).map((m) => ({
        ...(m.name ? { username: m.name } : {}),
        ...(m.email ? { email: m.email } : {}),
      })),
      ...(doc['dist-tags']?.latest ? { latestVersion: doc['dist-tags'].latest } : {}),
      ...(publishedAt ? { publishedAt } : {}),
      ...(doc.time?.created ? { createdAt: doc.time.created } : {}),
      ...(doc.time?.modified ? { lastPublishAt: doc.time.modified } : {}),
      ...(license ? { license } : {}),
      ...(repoUrl ? { repositoryUrl: repoUrl } : {}),
      ...(doc.homepage ? { homepage: doc.homepage } : {}),
      ...(versionInfo?.deprecated ? { deprecated: true } : {}),
      hasInstallScripts: Object.keys(scripts).length > 0,
      installScripts: scripts,
      ...(doc.versions ? { allVersions: Object.keys(doc.versions) } : {}),
    };
    return meta;
  }

  async fetchTarball(ref: PackageRef, ctx: ScanContext): Promise<FetchedTarball | null> {
    const doc = await this.#packument(ref.name, ctx);
    if (!doc) return null;
    const version = this.#resolveVersion(doc, ref.version);
    if (!version) return null;
    const tarballUrl = doc.versions?.[version]?.dist?.tarball;
    if (!tarballUrl) return null;
    try {
      const buffer = await ctx.http.getBuffer(tarballUrl);
      const extracted = await extractTarball(buffer);
      return {
        ref: { ...ref, version },
        extractedPath: extracted.extractedPath,
        totalBytes: extracted.totalBytes,
        fileCount: extracted.fileCount,
        dispose: extracted.dispose,
      };
    } catch (err) {
      ctx.logger.warn(`npm: failed to fetch/extract ${ref.name}@${version}: ${String(err)}`);
      return null;
    }
  }

  async popularNames(_ctx: ScanContext): Promise<string[]> {
    return [...popularNamesFor('npm')];
  }

  /** Fetch and cache the full npm packument for a package name. */
  async #packument(name: string, ctx: ScanContext): Promise<Packument | null> {
    const cached = ctx.cache.get<Packument>('npm-packument', name);
    if (cached) return cached;
    try {
      const url = `https://registry.npmjs.org/${name.replace('/', '%2F')}`;
      const doc = await ctx.http.getJson<Packument>(url);
      ctx.cache.set('npm-packument', name, doc, 6 * 60 * 60 * 1000);
      return doc;
    } catch {
      return null;
    }
  }

  #resolveVersion(doc: Packument, requested: string): string | undefined {
    if (requested && doc.versions?.[requested]) return requested;
    return (
      doc['dist-tags']?.latest ?? (doc.versions ? Object.keys(doc.versions).at(-1) : undefined)
    );
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

/** Keep only the auto-running install lifecycle scripts from a package's scripts. */
function filterLifecycle(scripts: Record<string, string> | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, command] of Object.entries(scripts ?? {})) {
    if (INSTALL_LIFECYCLE.has(name) && typeof command === 'string') result[name] = command;
  }
  return result;
}

function licenseString(license: LicenseField): string | undefined {
  if (!license) return undefined;
  return typeof license === 'string' ? license : license.type;
}

function repositoryUrl(repository: { url?: string } | string | undefined): string | undefined {
  if (!repository) return undefined;
  return typeof repository === 'string' ? repository : repository.url;
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
