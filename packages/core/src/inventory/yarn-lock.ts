import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope, ProjectRoot } from '../types/graph';
import { assignDepth, finalizeNodes, getOrCreateNode, type WorkingNode } from './working-graph';

export interface YarnPackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface YarnBlock {
  /** The `name@range` specs this resolved entry satisfies. */
  specs: string[];
  version?: string;
  /** Declared dependency ranges: name → range. */
  deps: Record<string, string>;
}

/**
 * Parse a Yarn Classic (v1) `yarn.lock` into resolved dependency nodes. The format
 * is custom (not YAML/JSON): each block's header lists every `name@range` that
 * dedupes to one resolved version, which is exactly the mapping needed to resolve
 * edges. Direct dependencies come from package.json.
 */
export function parseYarnLock(
  content: string,
  root: ProjectRoot,
  pkgJson: YarnPackageJson | null,
): DependencyNode[] {
  const blocks = parseBlocks(content);
  const specToVersion = new Map<string, string>();
  const working = new Map<string, WorkingNode>();

  // First pass: a node per resolved block, and the spec → version map.
  for (const block of blocks) {
    if (!block.version || block.specs.length === 0) continue;
    const name = nameFromSpec(block.specs[0]!);
    if (!name) continue;
    getOrCreateNode(working, { ecosystem: 'npm', name, version: block.version });
    for (const spec of block.specs) specToVersion.set(spec, block.version);
  }

  // Second pass: resolve edges via the spec map.
  for (const block of blocks) {
    if (!block.version) continue;
    const name = nameFromSpec(block.specs[0] ?? '');
    if (!name) continue;
    const parentKey = packageKey({ ecosystem: 'npm', name, version: block.version });
    const parent = working.get(parentKey);
    if (!parent) continue;
    for (const [depName, depRange] of Object.entries(block.deps)) {
      const childVersion = specToVersion.get(`${depName}@${depRange}`);
      if (!childVersion) continue;
      const childKey = packageKey({ ecosystem: 'npm', name: depName, version: childVersion });
      const child = working.get(childKey);
      if (child) {
        parent.dependencies.add(childKey);
        child.parents.add(parentKey);
      }
    }
  }

  // Direct dependencies from the manifest.
  const seeds: string[] = [];
  const sections: Array<[Record<string, string> | undefined, DependencyScope]> = [
    [pkgJson?.devDependencies, 'development'],
    [pkgJson?.optionalDependencies, 'optional'],
    [pkgJson?.dependencies, 'production'],
  ];
  for (const [deps, scope] of sections) {
    for (const [name, range] of Object.entries(deps ?? {})) {
      const version = specToVersion.get(`${name}@${range}`);
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

function parseBlocks(content: string): YarnBlock[] {
  const blocks: YarnBlock[] = [];
  const lines = content.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    // A block header is a non-indented, non-comment line ending in ':'.
    if (!line || line.startsWith('#') || /^\s/.test(line) || !line.trimEnd().endsWith(':')) {
      i++;
      continue;
    }
    const header = line.trimEnd().replace(/:$/, '');
    const specs = header.split(',').map((s) => unquote(s.trim()));
    i++;
    const block: YarnBlock = { specs, deps: {} };
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

/** The package name from a `name@range` spec (handles scoped names). */
function nameFromSpec(spec: string): string | null {
  const s = unquote(spec);
  const at = s.lastIndexOf('@');
  if (at <= 0) return null;
  return s.slice(0, at);
}

function unquote(s: string): string {
  return s.replace(/^"|"$/g, '');
}
