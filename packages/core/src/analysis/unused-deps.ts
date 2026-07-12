import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding } from '../types/finding';
import { collectImportedPackages } from './imports';

export interface UnusedResult {
  unused: string[];
  findings: Finding[];
}

interface PackageJson {
  dependencies?: Record<string, string>;
}

/**
 * Detect declared-but-unused production dependencies (SPEC.md §5): cross-reference
 * what package.json declares against what the source actually imports. Unused deps
 * are dead weight — attack surface with zero benefit. Only `dependencies` are
 * checked (devDependencies are frequently tools invoked via config, not imports).
 * npm/JS-TS only; Python import analysis is future work.
 */
export async function detectUnusedDependencies(projectRoot: string): Promise<UnusedResult> {
  const pkg = await readJson(join(projectRoot, 'package.json'));
  const declared = Object.keys(pkg?.dependencies ?? {});
  if (declared.length === 0) return { unused: [], findings: [] };

  const used = await collectImportedPackages(projectRoot);
  const unused = declared.filter((name) => !used.has(name) && !isImplicitlyUsed(name)).sort();
  return { unused, findings: unused.map(toFinding) };
}

/** Type-only packages are never imported directly but are legitimately declared. */
function isImplicitlyUsed(name: string): boolean {
  return name.startsWith('@types/');
}

function toFinding(name: string): Finding {
  return {
    ruleId: 'venom/unused-dependency',
    level: 'note',
    category: 'unused-dependency',
    title: `Unused dependency: ${name}`,
    message: `"${name}" is declared in dependencies but never imported in source — dead weight and attack surface with no benefit.`,
    locations: [{ uri: 'package.json' }],
    fingerprint: `unused:${name}`,
    remediation: `Remove "${name}" from dependencies if it is genuinely unused.`,
  };
}

async function readJson(path: string): Promise<PackageJson | null> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as PackageJson;
  } catch {
    return null;
  }
}
