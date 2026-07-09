import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { ScanContext } from '../types/context';
import type { PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { FetchedTarball, RegistryMetadata } from '../types/registry';
import { normalizePypiName, toPurl } from './purl';

interface WorkingNode {
  ref: PackageRef;
  direct: boolean;
  depth: number;
  scopes: Set<DependencyScope>;
  dependencies: Set<string>;
  parents: Set<string>;
}

interface PoetryPackage {
  name?: string;
  version?: string;
  category?: string;
  groups?: string[];
  dependencies?: Record<string, unknown>;
}

/**
 * smol-toml is ESM-only; core is CommonJS. Load it via dynamic import (preserved
 * as `import()` under node16 resolution) and memoize the parse function.
 */
let tomlParse: ((src: string) => unknown) | undefined;
async function getTomlParse(): Promise<(src: string) => unknown> {
  if (!tomlParse) {
    const mod = await import('smol-toml');
    tomlParse = mod.parse;
  }
  return tomlParse;
}

/**
 * PyPI ecosystem adapter (SPEC.md §4 M1). Prefers `poetry.lock`, which encodes a
 * fully-resolved dependency graph (versions + edges), and falls back to
 * `requirements.txt`. The requirements.txt path only yields pinned direct
 * dependencies — the format carries no transitive resolution, a limitation
 * documented here and surfaced to users rather than papered over.
 */
export class PypiAdapter implements EcosystemAdapter {
  readonly ecosystem = 'pypi' as const;

  async parseProject(projectRoot: string): Promise<EcosystemParseResult | null> {
    const poetry = await this.#readText(join(projectRoot, 'poetry.lock'));
    if (poetry) return this.#parsePoetry(poetry, projectRoot);

    const requirements = await this.#readText(join(projectRoot, 'requirements.txt'));
    if (requirements) return this.#parseRequirements(requirements, projectRoot);

    return null;
  }

  purl(ref: PackageRef): string {
    return toPurl(ref);
  }

  // Implemented in Module 3.
  async fetchMetadata(_ref: PackageRef, _ctx: ScanContext): Promise<RegistryMetadata | null> {
    return null;
  }
  async fetchTarball(_ref: PackageRef, _ctx: ScanContext): Promise<FetchedTarball | null> {
    return null;
  }
  async popularNames(_ctx: ScanContext): Promise<string[]> {
    return [];
  }

  async #readText(path: string): Promise<string | null> {
    try {
      return await readFile(path, 'utf8');
    } catch {
      return null;
    }
  }

  async #parsePoetry(lockContent: string, projectRoot: string): Promise<EcosystemParseResult> {
    const parseToml = await getTomlParse();
    const parsed = parseToml(lockContent) as { package?: PoetryPackage[] };
    const pkgs = (parsed.package ?? []).filter((p) => p.name && p.version);

    const working = new Map<string, WorkingNode>();
    const nameToKey = new Map<string, string>();

    for (const p of pkgs) {
      const ref: PackageRef = {
        ecosystem: 'pypi',
        name: normalizePypiName(p.name!),
        version: p.version!,
      };
      const key = packageKey(ref);
      nameToKey.set(ref.name, key);
      working.set(key, {
        ref,
        direct: false,
        depth: Number.POSITIVE_INFINITY,
        scopes: new Set([poetryScope(p)]),
        dependencies: new Set(),
        parents: new Set(),
      });
    }

    for (const p of pkgs) {
      const parentKey = nameToKey.get(normalizePypiName(p.name!));
      if (!parentKey) continue;
      for (const depName of Object.keys(p.dependencies ?? {})) {
        const childKey = nameToKey.get(normalizePypiName(depName));
        if (!childKey || childKey === parentKey) continue;
        working.get(parentKey)!.dependencies.add(childKey);
        working.get(childKey)!.parents.add(parentKey);
      }
    }

    const project = await readPyprojectMeta(projectRoot);
    const root: ProjectRoot = {
      name: project.name ?? basename(projectRoot),
      ...(project.version ? { version: project.version } : {}),
      path: projectRoot,
    };

    // Direct deps: from pyproject if available, else nodes with no parents.
    const seeds: string[] = [];
    if (project.directDeps.size > 0) {
      for (const [name, scope] of project.directDeps) {
        const key = nameToKey.get(name);
        if (!key) continue;
        const node = working.get(key)!;
        node.direct = true;
        node.depth = 1;
        node.scopes.add(scope);
        seeds.push(key);
      }
    } else {
      for (const [key, node] of working) {
        if (node.parents.size === 0) {
          node.direct = true;
          node.depth = 1;
          seeds.push(key);
        }
      }
    }

    assignDepth(working, seeds);
    return { root, nodes: finalizeNodes(working) };
  }

  #parseRequirements(content: string, projectRoot: string): EcosystemParseResult {
    const nodes: DependencyNode[] = [];
    const seen = new Set<string>();
    for (const raw of content.split(/\r?\n/)) {
      const parsed = parseRequirementLine(raw);
      if (!parsed) continue;
      const ref: PackageRef = { ecosystem: 'pypi', name: parsed.name, version: parsed.version };
      const key = packageKey(ref);
      if (seen.has(key)) continue;
      seen.add(key);
      nodes.push({
        ref,
        direct: true,
        depth: 1,
        scopes: ['production'],
        dependencies: [],
        parents: [],
      });
    }
    nodes.sort((a, b) => packageKey(a.ref).localeCompare(packageKey(b.ref)));
    return { root: { name: basename(projectRoot), path: projectRoot }, nodes };
  }
}

function poetryScope(p: PoetryPackage): DependencyScope {
  const groups = p.groups ?? (p.category ? [p.category] : []);
  if (groups.some((g) => g === 'dev' || g === 'test')) return 'development';
  return 'production';
}

interface PyprojectMeta {
  name?: string;
  version?: string;
  directDeps: Map<string, DependencyScope>;
}

/** Read root metadata and direct dependency names from pyproject.toml (best-effort). */
async function readPyprojectMeta(projectRoot: string): Promise<PyprojectMeta> {
  const directDeps = new Map<string, DependencyScope>();
  let raw: string;
  try {
    raw = await readFile(join(projectRoot, 'pyproject.toml'), 'utf8');
  } catch {
    return { directDeps };
  }
  let doc: Record<string, unknown>;
  try {
    const parseToml = await getTomlParse();
    doc = parseToml(raw) as Record<string, unknown>;
  } catch {
    return { directDeps };
  }

  const tool = (doc.tool ?? {}) as Record<string, unknown>;
  const poetry = (tool.poetry ?? {}) as Record<string, unknown>;
  const project = (doc.project ?? {}) as Record<string, unknown>;

  const name = (poetry.name as string) ?? (project.name as string) ?? undefined;
  const version = (poetry.version as string) ?? (project.version as string) ?? undefined;

  // Poetry production deps (a table; the implicit `python` entry is not a package).
  for (const depName of Object.keys((poetry.dependencies as object) ?? {})) {
    if (depName.toLowerCase() === 'python') continue;
    directDeps.set(normalizePypiName(depName), 'production');
  }
  // Poetry dev deps: modern groups + legacy dev-dependencies.
  const groups = (poetry.group ?? {}) as Record<string, { dependencies?: object }>;
  for (const group of Object.values(groups)) {
    for (const depName of Object.keys(group.dependencies ?? {})) {
      directDeps.set(normalizePypiName(depName), 'development');
    }
  }
  for (const depName of Object.keys((poetry['dev-dependencies'] as object) ?? {})) {
    directDeps.set(normalizePypiName(depName), 'development');
  }
  // PEP 621 dependencies (list of requirement strings).
  const projectDeps = project.dependencies;
  if (Array.isArray(projectDeps)) {
    for (const spec of projectDeps) {
      const parsed = parseRequirementName(String(spec));
      if (parsed) directDeps.set(parsed, 'production');
    }
  }

  const meta: PyprojectMeta = { directDeps };
  if (name !== undefined) meta.name = name;
  if (version !== undefined) meta.version = version;
  return meta;
}

interface ParsedRequirement {
  name: string;
  version: string;
}

const REQUIREMENT_RE = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(===|==)\s*([^\s;,]+)/;

/** Parse a pinned `name==version` requirement line; returns null for anything unpinned. */
function parseRequirementLine(raw: string): ParsedRequirement | null {
  const line = raw.trim();
  if (!line || line.startsWith('#') || line.startsWith('-')) return null;
  const match = REQUIREMENT_RE.exec(line);
  if (!match) return null;
  return { name: normalizePypiName(match[1]!), version: match[3]! };
}

/** Extract just the (normalized) name from a PEP 508 requirement string. */
function parseRequirementName(spec: string): string | null {
  const match = /^([A-Za-z0-9._-]+)/.exec(spec.trim());
  return match ? normalizePypiName(match[1]!) : null;
}

function assignDepth(working: Map<string, WorkingNode>, seeds: string[]): void {
  const queue = [...seeds];
  let head = 0;
  while (head < queue.length) {
    const node = working.get(queue[head++]!);
    if (!node) continue;
    for (const childKey of node.dependencies) {
      const child = working.get(childKey);
      if (child && child.depth > node.depth + 1) {
        child.depth = node.depth + 1;
        queue.push(childKey);
      }
    }
  }
  for (const node of working.values()) {
    if (!Number.isFinite(node.depth)) node.depth = node.direct ? 1 : 2;
  }
}

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
