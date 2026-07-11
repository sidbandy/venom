import type { ScanContext } from '../types/context';
import type { Ecosystem, PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyGraph } from '../types/graph';
import type { RegistryMetadata } from '../types/registry';
import type { UpdatePlanEntry, UpdateTier } from '../types/update';
import type { Vulnerability } from '../types/vulnerability';
import type { EcosystemAdapter } from '../types/adapter';
import { NpmAdapter } from '../inventory/npm-adapter';
import { PypiAdapter } from '../inventory/pypi-adapter';
import { mapWithConcurrency } from '../util/concurrency';
import { classifyBump, compareVersions, isPrerelease } from './version';

export interface UpdatePlanOptions {
  concurrency?: number;
}

const TIER_ORDER: Record<UpdateTier, number> = { safe: 0, recommended: 1, risky: 2 };

/**
 * Build a tiered update plan (SPEC.md §4 M5, §5). For each direct dependency it
 * finds the least-disruptive upgrade — preferring the minimal version that
 * resolves any known vulnerabilities, otherwise the latest — and classifies it as
 * safe / recommended / risky. Transitive deps update via their parents, so only
 * direct deps (the ones the developer controls) are planned.
 */
export async function buildUpdatePlan(
  graph: DependencyGraph,
  vulnerabilities: Vulnerability[],
  ctx: ScanContext,
  options: UpdatePlanOptions = {},
): Promise<UpdatePlanEntry[]> {
  const vulnsByPackage = new Map<string, Vulnerability[]>();
  for (const v of vulnerabilities) {
    const key = packageKey(v.affected);
    const list = vulnsByPackage.get(key);
    if (list) list.push(v);
    else vulnsByPackage.set(key, [v]);
  }

  const directNodes = [...graph.nodes.values()].filter((n) => n.direct);
  const adapters = new Map<Ecosystem, EcosystemAdapter>();

  const entries = await mapWithConcurrency(
    directNodes,
    options.concurrency ?? 8,
    async (node): Promise<UpdatePlanEntry | null> => {
      const adapter = adapterFor(adapters, node.ref.ecosystem);
      const meta = await adapter.fetchMetadata(node.ref, ctx);
      if (!meta) return null;
      return planFor(node.ref, meta, vulnsByPackage.get(packageKey(node.ref)) ?? []);
    },
  );

  return entries
    .filter((e): e is UpdatePlanEntry => e !== null)
    .sort((a, b) => {
      // Vulnerability-fixing updates first, then by tier, then by name.
      const fixDiff =
        Number(b.fixesVulnerabilities.length > 0) - Number(a.fixesVulnerabilities.length > 0);
      if (fixDiff !== 0) return fixDiff;
      if (TIER_ORDER[a.tier] !== TIER_ORDER[b.tier]) return TIER_ORDER[a.tier] - TIER_ORDER[b.tier];
      return a.current.name.localeCompare(b.current.name);
    });
}

function planFor(
  ref: PackageRef,
  meta: RegistryMetadata,
  vulns: Vulnerability[],
): UpdatePlanEntry | null {
  const eco = ref.ecosystem;
  const current = ref.version;
  const available = (meta.allVersions ?? []).filter((v) => !isPrerelease(v, eco));

  let target: string | undefined;
  let fixes: string[] = [];

  if (vulns.length > 0) {
    const fix = minimalFixTarget(current, vulns, available, eco);
    if (fix) {
      target = fix.version;
      fixes = fix.fixes;
    }
  }
  if (!target && meta.latestVersion && compareVersions(meta.latestVersion, current, eco) > 0) {
    target = meta.latestVersion;
  }
  if (!target || compareVersions(target, current, eco) <= 0) return null;

  const { tier, breaking } = classifyBump(current, target, eco);
  return {
    current: ref,
    targetVersion: target,
    tier,
    fixesVulnerabilities: fixes,
    breaking,
    ...(meta.repositoryUrl ? { changelogUrl: releasesUrl(meta.repositoryUrl) } : {}),
    reason: buildReason(tier, fixes, breaking),
  };
}

/** The lowest available version that resolves every fixable vulnerability. */
function minimalFixTarget(
  current: string,
  vulns: Vulnerability[],
  available: string[],
  eco: Ecosystem,
): { version: string; fixes: string[] } | undefined {
  let boundary = current;
  const fixes: string[] = [];
  for (const v of vulns) {
    const earliestFix = (v.fixedVersions ?? [])
      .filter((x) => compareVersions(x, current, eco) > 0)
      .sort((a, b) => compareVersions(a, b, eco))[0];
    if (earliestFix) {
      if (compareVersions(earliestFix, boundary, eco) > 0) boundary = earliestFix;
      fixes.push(v.id);
    }
  }
  if (fixes.length === 0) return undefined;

  const target =
    available
      .filter((x) => compareVersions(x, boundary, eco) >= 0)
      .sort((a, b) => compareVersions(a, b, eco))[0] ?? boundary;
  return { version: target, fixes };
}

function buildReason(tier: UpdateTier, fixes: string[], breaking: boolean): string {
  const fixNote = fixes.length > 0 ? ` Resolves ${fixes.join(', ')}.` : '';
  switch (tier) {
    case 'safe':
      return `Patch update — no breaking changes.${fixNote}`;
    case 'recommended':
      return `Minor update.${fixNote || ' Keeps the dependency current.'}`;
    case 'risky':
      return `Major update — ${breaking ? 'likely breaking; review before applying.' : 'review before applying.'}${fixNote}`;
  }
}

function releasesUrl(repositoryUrl: string): string {
  const clean = repositoryUrl
    .replace(/^git\+/, '')
    .replace(/\.git$/, '')
    .replace(/^git:\/\//, 'https://');
  return clean.includes('github.com') ? `${clean}/releases` : clean;
}

function adapterFor(
  cache: Map<Ecosystem, EcosystemAdapter>,
  ecosystem: Ecosystem,
): EcosystemAdapter {
  let adapter = cache.get(ecosystem);
  if (!adapter) {
    adapter = ecosystem === 'pypi' ? new PypiAdapter() : new NpmAdapter();
    cache.set(ecosystem, adapter);
  }
  return adapter;
}
