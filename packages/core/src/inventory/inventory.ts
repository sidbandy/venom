import type { EcosystemAdapter, EcosystemParseResult } from '../types/adapter';
import type { DependencyGraph } from '../types/graph';
import { VenomError } from '../errors';
import { buildDependencyGraph } from './build-graph';
import { NpmAdapter } from './npm-adapter';
import { PypiAdapter } from './pypi-adapter';

/** Raised when a project has no lockfile any registered adapter can parse. */
export class NoSupportedLockfileError extends VenomError {
  constructor(projectRoot: string) {
    super(
      'NO_LOCKFILE',
      `No supported lockfile found under ${projectRoot}. ` +
        `Venom understands npm (package-lock.json), pnpm, Yarn, and PyPI (poetry.lock, requirements.txt).`,
    );
    this.name = 'NoSupportedLockfileError';
  }
}

/** The adapters enabled by default: npm and PyPI (SPEC.md §14 v1 scope). */
export function defaultAdapters(): EcosystemAdapter[] {
  return [new NpmAdapter(), new PypiAdapter()];
}

/**
 * Module 1's entry point: build the complete dependency inventory for a project
 * by running every ecosystem adapter over its root and merging the results into
 * one graph. A repo with both npm and PyPI manifests produces a single
 * cross-ecosystem graph.
 */
export async function inventoryProject(
  projectRoot: string,
  adapters: EcosystemAdapter[] = defaultAdapters(),
): Promise<DependencyGraph> {
  const results: EcosystemParseResult[] = [];
  for (const adapter of adapters) {
    const result = await adapter.parseProject(projectRoot);
    if (result) results.push(result);
  }
  if (results.length === 0) {
    throw new NoSupportedLockfileError(projectRoot);
  }
  return buildDependencyGraph(results);
}
