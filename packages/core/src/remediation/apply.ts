import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { UpdatePlanEntry } from '../types/update';

export interface AppliedUpdate {
  name: string;
  from: string;
  to: string;
  section: string;
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

/**
 * Apply npm update entries to package.json by bumping each dependency's version
 * range to the target while preserving the range operator (`^`, `~`, exact, …).
 * Returns what changed; the caller reinstalls afterward. Non-npm entries are left
 * alone (their manifests vary and are not auto-edited in v1).
 */
export async function applyNpmUpdates(
  projectRoot: string,
  entries: UpdatePlanEntry[],
): Promise<AppliedUpdate[]> {
  const npmEntries = entries.filter((e) => e.current.ecosystem === 'npm');
  if (npmEntries.length === 0) return [];

  const path = join(projectRoot, 'package.json');
  const pkg = JSON.parse(await readFile(path, 'utf8')) as Record<string, Record<string, string>>;

  const applied: AppliedUpdate[] = [];
  for (const entry of npmEntries) {
    for (const section of SECTIONS) {
      const deps = pkg[section];
      if (!deps) continue;
      const spec = deps[entry.current.name];
      if (typeof spec !== 'string') continue;
      const next = bumpRange(spec, entry.targetVersion);
      if (next !== spec) {
        deps[entry.current.name] = next;
        applied.push({ name: entry.current.name, from: spec, to: next, section });
      }
      break;
    }
  }

  if (applied.length > 0) {
    await writeFile(path, `${JSON.stringify(pkg, null, 2)}\n`);
  }
  return applied;
}

/** Rewrite a version range to `target`, preserving the leading operator. */
function bumpRange(spec: string, target: string): string {
  if (/\s|\|\|/.test(spec)) return `^${target}`; // complex range → normalize to caret
  const prefix = /^[^\d]*/.exec(spec)?.[0] ?? '';
  return `${prefix}${target}`;
}
