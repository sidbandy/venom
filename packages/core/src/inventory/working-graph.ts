import type { PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyNode, DependencyScope } from '../types/graph';

/** A mutable node used while resolving a lockfile; frozen into a DependencyNode at the end. */
export interface WorkingNode {
  ref: PackageRef;
  direct: boolean;
  depth: number;
  scopes: Set<DependencyScope>;
  dependencies: Set<string>;
  parents: Set<string>;
}

/** Get (or create) the working node for a package ref, keyed by {@link packageKey}. */
export function getOrCreateNode(working: Map<string, WorkingNode>, ref: PackageRef): WorkingNode {
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
}

/** Shortest-path depth from the direct dependencies (BFS over resolved edges). */
export function assignDepth(working: Map<string, WorkingNode>, seeds: string[]): void {
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
  // Any node never reached gets a best-effort depth.
  for (const node of working.values()) {
    if (!Number.isFinite(node.depth)) node.depth = node.direct ? 1 : 2;
  }
}

/** Freeze working nodes into immutable DependencyNodes with deterministic ordering. */
export function finalizeNodes(working: Map<string, WorkingNode>): DependencyNode[] {
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
