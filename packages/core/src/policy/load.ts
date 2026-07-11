import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Policy } from '../types/policy';

// `.venom.yml` uses snake_case keys (the "policy as code" convention teams expect);
// we validate the shape and map to the camelCase Policy type.
const PolicyFileSchema = z
  .object({
    policy: z
      .object({
        max_cvss_severity: z.number().optional(),
        block_on_kev: z.boolean().optional(),
        min_maintainers: z.number().optional(),
        block_on_secrets: z.boolean().optional(),
        license_denylist: z.array(z.string()).optional(),
      })
      .optional(),
  })
  .optional();

/**
 * Load and validate a project's `.venom.yml` policy (SPEC.md §11). Returns
 * `undefined` when no policy file exists. Throws a clear error on malformed input.
 */
export async function loadPolicy(projectRoot: string): Promise<Policy | undefined> {
  for (const name of ['.venom.yml', '.venom.yaml']) {
    let raw: string;
    try {
      raw = await readFile(join(projectRoot, name), 'utf8');
    } catch {
      continue;
    }
    let parsed;
    try {
      parsed = PolicyFileSchema.parse(parseYaml(raw));
    } catch (err) {
      throw new Error(`Invalid ${name}: ${err instanceof Error ? err.message : String(err)}`);
    }
    const p = parsed?.policy;
    if (!p) return {};
    return {
      ...(p.max_cvss_severity !== undefined ? { maxCvssSeverity: p.max_cvss_severity } : {}),
      ...(p.block_on_kev !== undefined ? { blockOnKev: p.block_on_kev } : {}),
      ...(p.min_maintainers !== undefined ? { minMaintainers: p.min_maintainers } : {}),
      ...(p.block_on_secrets !== undefined ? { blockOnSecrets: p.block_on_secrets } : {}),
      ...(p.license_denylist !== undefined ? { licenseDenylist: p.license_denylist } : {}),
    };
  }
  return undefined;
}

/** Starter policy written by `venom init`. */
export const STARTER_POLICY = `# Venom policy — team standards enforced in CI (SPEC.md §11).
policy:
  max_cvss_severity: 7.0 # block merges introducing a CVE above this CVSS score
  block_on_kev: true # always block if CISA KEV-listed, regardless of score
  min_maintainers: 1 # warn (not block) below this
  block_on_secrets: true
  license_denylist:
    - AGPL-3.0
`;
