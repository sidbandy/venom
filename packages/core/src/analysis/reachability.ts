import { packageKey } from '../types/ecosystem';
import type { DependencyGraph } from '../types/graph';
import { collectImportedPackages } from './imports';

/**
 * Package-level reachability analysis (future.md "Bigger bets"). Most CVEs live in
 * transitive dependencies your code never actually pulls in — they inflate the
 * finding count without representing real exposure. This computes which packages
 * are reachable from the project's *own* imports, by seeding from the direct
 * dependencies the source actually `import`s/`require`s and walking the resolved
 * dependency graph.
 *
 * This is package-level (not symbol-level) reachability: it answers "does any code
 * path my project imports lead to this package?" — a strong, honest first cut that
 * turns a long CVE list into the subset that can actually matter. (Symbol-level
 * call-graph reachability is a further refinement; see future.md.)
 */
export async function computeReachablePackages(
  projectRoot: string,
  graph: DependencyGraph,
): Promise<Set<string>> {
  const imported = await collectImportedPackages(projectRoot);
  const reachable = new Set<string>();
  const queue: string[] = [];

  // Seed from any resolved package the project's source actually imports.
  for (const node of graph.nodes.values()) {
    if (imported.has(node.ref.name)) {
      const key = packageKey(node.ref);
      if (!reachable.has(key)) {
        reachable.add(key);
        queue.push(key);
      }
    }
  }

  // Walk the resolved dependency edges: anything a reachable package depends on is
  // itself reachable.
  let head = 0;
  while (head < queue.length) {
    const node = graph.nodes.get(queue[head++]!);
    if (!node) continue;
    for (const childKey of node.dependencies) {
      if (!reachable.has(childKey)) {
        reachable.add(childKey);
        queue.push(childKey);
      }
    }
  }

  return reachable;
}
