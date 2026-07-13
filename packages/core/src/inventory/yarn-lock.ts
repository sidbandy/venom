import { parse as parseYaml } from 'yaml';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import { assignDepth, finalizeNodes, getOrCreateNode, type WorkingNode } from './working-graph';

export interface YarnPackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface YarnBlock {
  /** The `name@range` (or `name@npm:range`) specs this resolved entry satisfies. */
  specs: string[];
  version?: string;
  /** Declared dependency descriptors: name → range/descriptor. */
  deps: Record<string, string>;
}

/**
 * Parse a `yarn.lock` — both Yarn Classic (v1, a custom format) and Yarn Berry
 * (v2+, which is YAML) — into resolved dependency nodes feeding the npm graph.
 * Each entry's header lists every descriptor that dedupes to one resolved
 * version, which is exactly the mapping needed to resolve edges; direct
 * dependencies come from package.json.
 */
export function parseYarnLock(
  content: string,
  root: ProjectRoot,
  pkgJson: YarnPackageJson | null,
): DependencyNode[] {
  const blocks = content.includes('__metadata:') ? parseBerry(content) : parseClassic(content);
  return buildFromBlocks(blocks, root, pkgJson);
}

/** Shared: turn resolved blocks + the manifest into dependency nodes. */
function buildFromBlocks(
  blocks: YarnBlock[],
  _root: ProjectRoot,
  pkgJson: YarnPackageJson | null,
): DependencyNode[] {
  const specToVersion = new Map<string, string>();
  const working = new Map<string, WorkingNode>();

  for (const block of blocks) {
    if (!block.version || block.specs.length === 0) continue;
    const name = nameFromSpec(block.specs[0]!);
    if (!name) continue;
    getOrCreateNode(working, { ecosystem: 'npm', name, version: block.version });
    for (const spec of block.specs) {
      // Register both the raw descriptor and a protocol-stripped form, so both
      // Berry (`name@npm:range`) and manifest (`name@range`) lookups resolve.
      specToVersion.set(spec, block.version);
      specToVersion.set(stripProtocol(spec), block.version);
    }
  }

  for (const block of blocks) {
    if (!block.version) continue;
    const name = nameFromSpec(block.specs[0] ?? '');
    if (!name) continue;
    const parentKey = packageKey({ ecosystem: 'npm', name, version: block.version });
    const parent = working.get(parentKey);
    if (!parent) continue;
    for (const [depName, depRange] of Object.entries(block.deps)) {
      const childVersion =
        specToVersion.get(`${depName}@${depRange}`) ??
        specToVersion.get(stripProtocol(`${depName}@${depRange}`));
      if (!childVersion) continue;
      const childKey = packageKey({ ecosystem: 'npm', name: depName, version: childVersion });
      const child = working.get(childKey);
      if (child) {
        parent.dependencies.add(childKey);
        child.parents.add(parentKey);
      }
    }
  }

  const seeds: string[] = [];
  const sections: Array<[Record<string, string> | undefined, DependencyScope]> = [
    [pkgJson?.devDependencies, 'development'],
    [pkgJson?.optionalDependencies, 'optional'],
    [pkgJson?.dependencies, 'production'],
  ];
  for (const [deps, scope] of sections) {
    for (const [name, range] of Object.entries(deps ?? {})) {
      const version =
        specToVersion.get(`${name}@${range}`) ?? specToVersion.get(`${name}@npm:${range}`);
      if (!version) continue;
      const node = getOrCreateNode(working, { ecosystem: 'npm', name, version });
      node.direct = true;
      node.depth = 1;
      node.scopes.add(scope);
      seeds.push(packageKey(node.ref));
    }
  }

  assignDepth(working, seeds);
  return finalizeNodes(working);
}

/** Yarn Berry (v2+): the lockfile is YAML. */
function parseBerry(content: string): YarnBlock[] {
  let doc: Record<string, { version?: string; dependencies?: Record<string, string> }>;
  try {
    doc = parseYaml(content) as typeof doc;
  } catch {
    return [];
  }
  const blocks: YarnBlock[] = [];
  for (const [key, entry] of Object.entries(doc)) {
    if (key === '__metadata' || !entry || typeof entry !== 'object') continue;
    const block: YarnBlock = { specs: key.split(',').map((s) => unquote(s.trim())), deps: {} };
    if (entry.version) block.version = entry.version;
    for (const [depName, descriptor] of Object.entries(entry.dependencies ?? {})) {
      block.deps[depName] = String(descriptor);
    }
    blocks.push(block);
  }
  return blocks;
}

/** Yarn Classic (v1): a custom, indentation-based format. */
function parseClassic(content: string): YarnBlock[] {
  const blocks: YarnBlock[] = [];
  const lines = content.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (!line || line.startsWith('#') || /^\s/.test(line) || !line.trimEnd().endsWith(':')) {
      i++;
      continue;
    }
    const header = line.trimEnd().replace(/:$/, '');
    const block: YarnBlock = { specs: header.split(',').map((s) => unquote(s.trim())), deps: {} };
    i++;
    let inDeps = false;
    while (i < lines.length && /^\s/.test(lines[i]!)) {
      const l = lines[i]!;
      const versionMatch = /^\s+version:?\s+"?([^"]+)"?\s*$/.exec(l);
      if (versionMatch?.[1]) block.version = versionMatch[1];
      if (/^\s+(optional)?[Dd]ependencies:\s*$/.test(l)) {
        inDeps = /dependencies:/i.test(l);
      } else if (inDeps) {
        const depMatch = /^\s+("?[^"\s]+"?)\s+"?([^"]+)"?\s*$/.exec(l);
        if (depMatch) block.deps[unquote(depMatch[1]!)] = depMatch[2]!;
      }
      i++;
    }
    blocks.push(block);
  }
  return blocks;
}

/** The package name from a `name@range` / `name@npm:range` spec (handles scopes). */
function nameFromSpec(spec: string): string | null {
  const s = unquote(spec);
  const at = s.lastIndexOf('@');
  if (at <= 0) return null;
  return s.slice(0, at);
}

/** Drop a Berry protocol from a descriptor: `name@npm:^1.0.0` → `name@^1.0.0`. */
function stripProtocol(spec: string): string {
  return spec.replace('@npm:', '@');
}

function unquote(s: string): string {
  return s.replace(/^"|"$/g, '');
}
