import type { ScanContext } from '../types/context';
import type { Ecosystem, PackageRef } from '../types/ecosystem';
import type { Finding, FindingLevel } from '../types/finding';
import type { EcosystemAdapter } from '../types/adapter';
import type { RegistryMetadata } from '../types/registry';
import { NpmAdapter } from '../inventory/npm-adapter';
import { PypiAdapter } from '../inventory/pypi-adapter';
import { toPurl } from '../inventory/purl';
import { inspectInstallScripts } from './install-scripts';
import { scanSourceTree } from './scan-source-tree';
import type { AstSignalKind } from './ast-scan';

/** Newly-introduced code capabilities that strongly suggest a malicious update. */
const FLAG_KINDS = new Set<AstSignalKind>([
  'child-process',
  'dynamic-eval',
  'network',
  'obfuscation',
]);
const TRACKED_KINDS: AstSignalKind[] = [
  'child-process',
  'dynamic-eval',
  'network',
  'env-access',
  'obfuscation',
  'filesystem',
];

export type DiffVerdict = 'clear' | 'caution' | 'flagged';

export interface VersionDiff {
  package: string;
  ecosystem: Ecosystem;
  from: string;
  to: string;
  maintainersAdded: string[];
  maintainersRemoved: string[];
  /** True if the old version had build provenance and the new one dropped it. */
  provenanceLost: boolean;
  /** Install lifecycle scripts newly present or changed in the new version. */
  installScriptsChanged: string[];
  /** Code capabilities that appear more in the new version than the old. */
  capabilitiesIntroduced: AstSignalKind[];
  /** Source files carrying newly-dangerous install-script content. */
  dangerousInstallScripts: string[];
  entropyFileDelta: number;
  verdict: DiffVerdict;
  reasons: string[];
  findings: Finding[];
}

/**
 * Version-diff threat detection (future.md "Bigger bets"). The attacks that
 * matter most — event-stream, xz — are *updates* that turn a trusted package
 * malicious. Rather than judging a version in isolation, this compares two
 * versions and flags the security-relevant delta: new maintainers (ownership
 * handoff), newly-added install scripts, and dangerous code capabilities
 * (process spawning, eval, network, obfuscated blobs) that the old version didn't
 * have. Both versions are downloaded and analyzed **without being executed**.
 */
export interface DiffOptions {
  /** Inject the ecosystem adapter (mainly for tests). */
  adapter?: EcosystemAdapter;
}

export async function diffVersions(
  ecosystem: Ecosystem,
  name: string,
  from: string,
  to: string,
  ctx: ScanContext,
  options: DiffOptions = {},
): Promise<VersionDiff> {
  const adapter: EcosystemAdapter =
    options.adapter ?? (ecosystem === 'pypi' ? new PypiAdapter() : new NpmAdapter());
  const refFrom: PackageRef = { ecosystem, name, version: from };
  const refTo: PackageRef = { ecosystem, name, version: to };

  const [metaFrom, metaTo] = await Promise.all([
    adapter.fetchMetadata(refFrom, ctx),
    adapter.fetchMetadata(refTo, ctx),
  ]);

  const fromMaintainers = maintainerSet(metaFrom);
  const toMaintainers = maintainerSet(metaTo);
  const maintainersAdded = [...toMaintainers].filter((m) => !fromMaintainers.has(m)).sort();
  const maintainersRemoved = [...fromMaintainers].filter((m) => !toMaintainers.has(m)).sort();

  const provenanceLost = Boolean(metaFrom?.hasProvenance) && !metaTo?.hasProvenance;
  const installScriptsChanged = changedScripts(metaFrom, metaTo);
  const dangerousInstallScripts = inspectInstallScripts(metaTo?.installScripts)
    .filter(
      (s) => !inspectInstallScripts(metaFrom?.installScripts).some((f) => f.script === s.script),
    )
    .map((s) => `${s.script}: ${s.reasons.join('; ')}`);

  const [analysisFrom, analysisTo] = await Promise.all([
    analyzeTarball(adapter, refFrom, ctx),
    analyzeTarball(adapter, refTo, ctx),
  ]);
  const capabilitiesIntroduced = TRACKED_KINDS.filter(
    (k) => (analysisTo.counts[k] ?? 0) > (analysisFrom.counts[k] ?? 0),
  );
  const entropyFileDelta = analysisTo.entropyFiles - analysisFrom.entropyFiles;

  const reasons: string[] = [];
  if (maintainersAdded.length > 0)
    reasons.push(`New maintainer(s): ${maintainersAdded.join(', ')}`);
  if (provenanceLost)
    reasons.push('Build provenance was removed (the previous version had a signed attestation)');
  for (const s of dangerousInstallScripts) reasons.push(`New dangerous install script — ${s}`);
  for (const k of capabilitiesIntroduced) {
    reasons.push(
      `Introduced ${k} capability (${analysisFrom.counts[k] ?? 0} → ${analysisTo.counts[k] ?? 0} occurrences)`,
    );
  }
  if (installScriptsChanged.length > 0)
    reasons.push(`Install scripts changed: ${installScriptsChanged.join(', ')}`);
  if (entropyFileDelta > 0)
    reasons.push(`${entropyFileDelta} new high-entropy (possibly encoded) file(s)`);

  const flagged =
    dangerousInstallScripts.length > 0 || capabilitiesIntroduced.some((k) => FLAG_KINDS.has(k));
  const caution =
    maintainersAdded.length > 0 ||
    provenanceLost ||
    installScriptsChanged.length > 0 ||
    entropyFileDelta > 0 ||
    capabilitiesIntroduced.length > 0;
  const verdict: DiffVerdict = flagged ? 'flagged' : caution ? 'caution' : 'clear';

  const findings = buildFindings(refTo, verdict, reasons);
  return {
    package: name,
    ecosystem,
    from,
    to,
    maintainersAdded,
    maintainersRemoved,
    provenanceLost,
    installScriptsChanged,
    capabilitiesIntroduced,
    dangerousInstallScripts,
    entropyFileDelta,
    verdict,
    reasons,
    findings,
  };
}

interface TarballAnalysis {
  counts: Partial<Record<AstSignalKind, number>>;
  entropyFiles: number;
}

async function analyzeTarball(
  adapter: EcosystemAdapter,
  ref: PackageRef,
  ctx: ScanContext,
): Promise<TarballAnalysis> {
  const tarball = await adapter.fetchTarball(ref, ctx);
  if (!tarball) return { counts: {}, entropyFiles: 0 };
  try {
    const counts: Partial<Record<AstSignalKind, number>> = {};
    let entropyFiles = 0;
    for (const sf of await scanSourceTree(tarball.extractedPath)) {
      for (const signal of sf.astSignals) counts[signal.kind] = (counts[signal.kind] ?? 0) + 1;
      if (sf.entropyHits.length > 0) entropyFiles++;
    }
    return { counts, entropyFiles };
  } finally {
    await tarball.dispose();
  }
}

function maintainerSet(meta: RegistryMetadata | null): Set<string> {
  return new Set((meta?.maintainers ?? []).map((m) => m.username ?? m.email ?? '').filter(Boolean));
}

function changedScripts(from: RegistryMetadata | null, to: RegistryMetadata | null): string[] {
  const fromScripts = from?.installScripts ?? {};
  const toScripts = to?.installScripts ?? {};
  const changed: string[] = [];
  for (const [name, cmd] of Object.entries(toScripts)) {
    if (fromScripts[name] !== cmd) changed.push(name);
  }
  return changed.sort();
}

function buildFindings(ref: PackageRef, verdict: DiffVerdict, reasons: string[]): Finding[] {
  if (verdict === 'clear') return [];
  const level: FindingLevel = verdict === 'flagged' ? 'error' : 'warning';
  return [
    {
      ruleId: 'venom/version-diff',
      level,
      category: 'malicious',
      title: `Suspicious changes in ${ref.name}@${ref.version}`,
      message: reasons.join(' '),
      locations: [{ uri: toPurl(ref) }],
      fingerprint: `version-diff:${ref.name}@${ref.version}`,
      relatedPackage: ref,
      properties: { verdict, reasons },
    },
  ];
}
