import type { DependencyGraph } from '../../types/graph';
import { toSpdx, type SpdxDocument } from './spdx';
import { toCycloneDx, type CycloneDxDocument } from './cyclonedx';
import type { SbomOptions } from './types';

export { toSpdx } from './spdx';
export type { SpdxDocument } from './spdx';
export { toCycloneDx } from './cyclonedx';
export type { CycloneDxDocument } from './cyclonedx';
export type { SbomOptions } from './types';

export type SbomFormat = 'spdx' | 'cyclonedx';

/** Generate an SBOM in the requested format and serialize it to pretty JSON. */
export function generateSbom(
  graph: DependencyGraph,
  format: SbomFormat,
  options?: SbomOptions,
): string {
  const doc: SpdxDocument | CycloneDxDocument =
    format === 'spdx' ? toSpdx(graph, options) : toCycloneDx(graph, options);
  return JSON.stringify(doc, null, 2);
}
