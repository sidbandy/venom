import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { DependencyGraph } from '../types/graph';
import type { Finding } from '../types/finding';

export interface LicenseResult {
  findings: Finding[];
  /** Count of packages per resolved license id. */
  byLicense: Record<string, number>;
  unknown: number;
}

export interface LicenseOptions {
  /** SPDX license ids that must not appear (from `.venom.yml`). Default: AGPL family. */
  denylist?: string[];
  /** The project's own license, for copyleft-conflict detection. */
  projectLicense?: string;
}

const DEFAULT_DENYLIST = ['AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later'];
const PERMISSIVE = /^(MIT|ISC|Apache-2\.0|BSD-[23]-Clause|0BSD|Unlicense|CC0-1\.0)$/i;
const STRONG_COPYLEFT = /^(A?GPL-[23]|GPL-[23])/i;

/**
 * License compliance check (SPEC.md §5): flag denylisted licenses, strong-copyleft
 * dependencies that conflict with a permissive project (e.g. an MIT app pulling in
 * AGPL — which can legally obligate open-sourcing the whole application), and
 * dependencies with no declared license. Reads installed license metadata from
 * `node_modules` (offline). npm-focused; PyPI license data is future work.
 */
export async function checkLicenses(
  projectRoot: string,
  graph: DependencyGraph,
  options: LicenseOptions = {},
): Promise<LicenseResult> {
  const denylist = new Set((options.denylist ?? DEFAULT_DENYLIST).map((l) => l.toLowerCase()));
  const projectPermissive = options.projectLicense ? PERMISSIVE.test(options.projectLicense) : true;

  const { licenses, installed } = await readInstalledLicenses(projectRoot);
  const findings: Finding[] = [];
  const byLicense: Record<string, number> = {};
  let unknown = 0;

  const npmNames = new Set(
    [...graph.nodes.values()].filter((n) => n.ref.ecosystem === 'npm').map((n) => n.ref.name),
  );

  for (const name of [...npmNames].sort()) {
    // Skip packages not present in node_modules (e.g. other-platform optional deps):
    // we have no license data for them offline, so reporting "unknown" would be noise.
    if (!installed.has(name)) continue;

    const license = licenses.get(name);
    if (!license) {
      unknown++;
      byLicense['UNKNOWN'] = (byLicense['UNKNOWN'] ?? 0) + 1;
      findings.push(
        licenseFinding(
          'venom/license-unknown',
          'note',
          name,
          'no declared license',
          `"${name}" is installed but declares no license — legal status is unclear.`,
        ),
      );
      continue;
    }
    byLicense[license] = (byLicense[license] ?? 0) + 1;

    if (denylist.has(license.toLowerCase())) {
      findings.push(
        licenseFinding(
          'venom/license-denylist',
          'error',
          name,
          license,
          `"${name}" is licensed ${license}, which is on the deny list.`,
        ),
      );
    } else if (projectPermissive && STRONG_COPYLEFT.test(license)) {
      findings.push(
        licenseFinding(
          'venom/license-conflict',
          'warning',
          name,
          license,
          `"${name}" is ${license} (strong copyleft) in a permissively-licensed project — this can obligate open-sourcing your application.`,
        ),
      );
    }
  }

  return { findings, byLicense, unknown };
}

function licenseFinding(
  ruleId: string,
  level: Finding['level'],
  name: string,
  license: string,
  message: string,
): Finding {
  return {
    ruleId,
    level,
    category: 'license',
    title: `${name}: ${license}`,
    message,
    locations: [{ uri: `node_modules/${name}/package.json` }],
    fingerprint: `${ruleId}:${name}`,
    remediation:
      'Review the license, replace the dependency, or add an approved exception to .venom.yml.',
    properties: { package: name, license },
  };
}

interface InstalledLicenses {
  /** name → normalized license id (only packages that declare one). */
  licenses: Map<string, string>;
  /** Every package actually present in node_modules (declared license or not). */
  installed: Set<string>;
}

/** Read license metadata for every package present in node_modules. */
async function readInstalledLicenses(projectRoot: string): Promise<InstalledLicenses> {
  const licenses = new Map<string, string>();
  const installed = new Set<string>();
  const nodeModules = join(projectRoot, 'node_modules');
  let entries;
  try {
    entries = await readdir(nodeModules, { withFileTypes: true });
  } catch {
    return { licenses, installed };
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('@')) {
      // Scoped packages: one more level down.
      let scoped;
      try {
        scoped = await readdir(join(nodeModules, entry.name), { withFileTypes: true });
      } catch {
        continue;
      }
      for (const s of scoped) {
        if (s.isDirectory()) {
          await addLicense(
            licenses,
            installed,
            `${entry.name}/${s.name}`,
            join(nodeModules, entry.name, s.name),
          );
        }
      }
    } else if (!entry.name.startsWith('.')) {
      await addLicense(licenses, installed, entry.name, join(nodeModules, entry.name));
    }
  }
  return { licenses, installed };
}

async function addLicense(
  licenses: Map<string, string>,
  installed: Set<string>,
  name: string,
  dir: string,
): Promise<void> {
  try {
    const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8')) as {
      license?: unknown;
      licenses?: Array<{ type?: string }>;
    };
    installed.add(name);
    const license = normalizeLicense(pkg.license) ?? pkg.licenses?.[0]?.type;
    if (license) licenses.set(name, license);
  } catch {
    // no package.json / unreadable → not counted as installed
  }
}

function normalizeLicense(license: unknown): string | undefined {
  if (typeof license === 'string') return license;
  if (license && typeof license === 'object' && 'type' in license) {
    const t = (license as { type?: unknown }).type;
    return typeof t === 'string' ? t : undefined;
  }
  return undefined;
}
