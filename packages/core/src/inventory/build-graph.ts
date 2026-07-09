import type { EcosystemParseResult } from '../types/adapter';
import type { Ecosystem } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyGraph, DependencyNode } from '../types/graph';

/**
 * Merge one-or-more per-ecosystem parse results into a single
 * {@link DependencyGraph}. Keys are ecosystem-namespaced (`packageKey`), so a
 * repo with both npm and PyPI manifests yields one unified graph with no
 * cross-ecosystem collisions.
 */
export function buildDependencyGraph(results: EcosystemParseResult[]): DependencyGraph {
  if (results.length === 0) {
    throw new Error('buildDependencyGraph requires at least one parse result');
  }

  const nodes = new Map<string, DependencyNode>();
  for (const result of results) {
    for (const node of result.nodes) {
      const key = packageKey(node.ref);
      const existing = nodes.get(key);
      nodes.set(key, existing ? mergeNodes(existing, node) : node);
    }
  }

  const ecosystems = [...new Set([...nodes.values()].map((n) => n.ref.ecosystem))].sort();
  return { root: results[0]!.root, ecosystems, nodes };
}

/** Combine two nodes that resolved to the same package (defensive; rare in practice). */
function mergeNodes(a: DependencyNode, b: DependencyNode): DependencyNode {
  return {
    ref: a.ref,
    direct: a.direct || b.direct,
    depth: Math.min(a.depth, b.depth),
    scopes: unionSorted(a.scopes, b.scopes),
    dependencies: unionSorted(a.dependencies, b.dependencies),
    parents: unionSorted(a.parents, b.parents),
  };
}

function unionSorted<T>(a: readonly T[], b: readonly T[]): T[] {
  return [...new Set([...a, ...b])].sort();
}

export interface InventorySummary {
  /** Total resolved packages (excludes the root project). */
  total: number;
  direct: number;
  transitive: number;
  ecosystems: Ecosystem[];
  /** Deepest transitive chain length. */
  maxDepth: number;
  byEcosystem: Record<string, number>;
}

/** Roll a graph up into the headline numbers the CLI and Health Score report on. */
export function summarizeGraph(graph: DependencyGraph): InventorySummary {
  let direct = 0;
  let maxDepth = 0;
  const byEcosystem: Record<string, number> = {};
  for (const node of graph.nodes.values()) {
    if (node.direct) direct += 1;
    if (Number.isFinite(node.depth)) maxDepth = Math.max(maxDepth, node.depth);
    byEcosystem[node.ref.ecosystem] = (byEcosystem[node.ref.ecosystem] ?? 0) + 1;
  }
  const total = graph.nodes.size;
  return {
    total,
    direct,
    transitive: total - direct,
    ecosystems: graph.ecosystems,
    maxDepth,
    byEcosystem,
  };
}
