import type { Ecosystem, PackageRef } from './ecosystem';

/** How a dependency is required — mirrors manifest dependency sections. */
export type DependencyScope = 'production' | 'development' | 'optional' | 'peer';

/**
 * The project being analyzed (the root of the dependency graph). This is the
 * user's own code, not a dependency.
 */
export interface ProjectRoot {
  name: string;
  version?: string;
  /** Absolute path to the project root on disk. */
  path: string;
}

/**
 * One resolved package in the dependency tree. A node is unique per
 * name+version+ecosystem; the same package pulled in by several parents is a
 * single node with multiple `parents`.
 */
export interface DependencyNode {
  ref: PackageRef;
  /** True when the root project depends on this package directly. */
  direct: boolean;
  /** Shortest distance from the root project. Direct dependencies are depth 1. */
  depth: number;
  /** Every way this package is depended upon across the tree. */
  scopes: DependencyScope[];
  /** `packageKey`s of this node's own resolved dependencies. */
  dependencies: string[];
  /** `packageKey`s of nodes that depend on this one (empty for direct-of-root only). */
  parents: string[];
}

/**
 * The complete inventory produced by Module 1: the root project plus every
 * direct and transitive dependency, keyed by {@link packageKey}. A single graph
 * can span multiple ecosystems (e.g. a repo with both npm and PyPI manifests).
 */
export interface DependencyGraph {
  root: ProjectRoot;
  ecosystems: Ecosystem[];
  /** All packages, keyed by `packageKey(node.ref)`. */
  nodes: Map<string, DependencyNode>;
}
