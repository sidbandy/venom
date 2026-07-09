import type { ScanContext } from './context';
import type { Ecosystem, PackageRef } from './ecosystem';
import type { DependencyNode, ProjectRoot } from './graph';
import type { FetchedTarball, RegistryMetadata } from './registry';

/** Raw result of parsing one ecosystem's manifests/lockfiles under a project. */
export interface EcosystemParseResult {
  root: ProjectRoot;
  /** Flat list of resolved nodes; the inventory layer merges these into a graph. */
  nodes: DependencyNode[];
}

/**
 * The single abstraction that keeps npm and PyPI from forking the engine. Every
 * module consumes packages through this interface and never talks to a specific
 * registry directly. Adding a future ecosystem (out of scope for v1 — SPEC.md
 * §14) means implementing this once.
 */
export interface EcosystemAdapter {
  readonly ecosystem: Ecosystem;

  /**
   * Detect and parse this ecosystem's lockfile(s) under `projectRoot`. Returns
   * `null` when the ecosystem is not present in the project.
   */
  parseProject(projectRoot: string): Promise<EcosystemParseResult | null>;

  /** Registry metadata for maintainer risk / health cards (Module 3, Section 5). */
  fetchMetadata(ref: PackageRef, ctx: ScanContext): Promise<RegistryMetadata | null>;

  /**
   * Download and safely extract a package tarball **without running it**
   * (Module 3 install-script inspection / entropy / AST scanning).
   */
  fetchTarball(ref: PackageRef, ctx: ScanContext): Promise<FetchedTarball | null>;

  /**
   * Popularity-ranked list of top package names, for typosquat distance checks
   * (Module 3). Bundled offline so the check works with no network.
   */
  popularNames(ctx: ScanContext): Promise<string[]>;

  /** Build a Package URL (purl) for SBOM output, e.g. `pkg:npm/lodash@4.17.21`. */
  purl(ref: PackageRef): string;
}
