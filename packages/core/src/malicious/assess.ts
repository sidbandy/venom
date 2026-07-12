import type { ScanContext } from '../types/context';
import type { Ecosystem, PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyGraph } from '../types/graph';
import type { Finding, FindingLevel } from '../types/finding';
import type { EcosystemAdapter } from '../types/adapter';
import { NpmAdapter } from '../inventory/npm-adapter';
import { PypiAdapter } from '../inventory/pypi-adapter';
import { toPurl } from '../inventory/purl';
import { mapWithConcurrency } from '../util/concurrency';
import { detectTyposquat } from './typosquat';
import { detectHomoglyphs } from './homoglyph';
import { popularNamesForAll } from './popular-names';
import { assessMaintainerRisk } from './maintainer-risk';
import { inspectInstallScripts } from './install-scripts';
import { scanSourceTree } from './scan-source-tree';

/** The Bouncer verdict for a package (SPEC.md §6). */
export type BouncerVerdict = 'clear' | 'caution' | 'flagged';

export interface PackageAssessment {
  ref: PackageRef;
  verdict: BouncerVerdict;
  /** Human-readable supporting reasons, in the order they were found. */
  reasons: string[];
  findings: Finding[];
}

export interface AssessOptions {
  /** Download + statically analyze the package tarball (AST + entropy). */
  deep?: boolean;
  /** Fetch registry metadata (maintainer risk, install scripts). */
  metadata?: boolean;
  /**
   * Flag when the package can't be found in the registry. On for the Bouncer
   * (a name that doesn't resolve is often a typo or an unpublished squat); off
   * for tree scans, where an installed dependency is known to exist.
   */
  flagNotFound?: boolean;
  /** Clock injection for deterministic tests. */
  now?: Date;
}

const LEVEL_RANK: Record<FindingLevel, number> = { note: 1, warning: 2, error: 3 };

/**
 * Assess a single package for malicious-package signals. This is the dual-mode
 * core (SPEC.md §4 M3, §6): it works identically whether the `ref` is an
 * already-installed dependency (audit) or a candidate someone is about to install
 * (the Bouncer). Which checks run is controlled by {@link AssessOptions}.
 */
export async function assessPackage(
  adapter: EcosystemAdapter,
  ref: PackageRef,
  ctx: ScanContext,
  options: AssessOptions = {},
): Promise<PackageAssessment> {
  const findings: Finding[] = [];
  const reasons: string[] = [];
  const record = (finding: Finding, reason: string): void => {
    findings.push(finding);
    reasons.push(reason);
  };

  // Resolve metadata first so findings can carry the concrete version.
  const meta = options.metadata === false ? null : await adapter.fetchMetadata(ref, ctx);
  const subject = meta?.ref ?? ref;

  // The package doesn't resolve in the registry — likely a typo or a squat that
  // isn't published (yet). Only meaningful when we actually asked and are online.
  if (options.flagNotFound && !meta && options.metadata !== false && !ctx.config.offline) {
    const reason = 'Package not found in the registry — likely a typo or unpublished name';
    record(
      make('venom/not-found', 'warning', subject, 'Package not found in registry', reason),
      reason,
    );
  }

  // --- Name-based checks (offline, always run) ---
  // Match against the union of ecosystems' popular names (cross-ecosystem squats).
  const typo = detectTyposquat(ref.name, popularNamesForAll());
  if (typo.suspicious) {
    const reason = `Levenshtein distance ${typo.distance} from popular package "${typo.target}"`;
    record(
      make('venom/typosquat', 'error', subject, `Possible typosquat of "${typo.target}"`, reason),
      reason,
    );
  }
  const homo = detectHomoglyphs(ref.name);
  if (homo.suspicious && homo.reason) {
    record(
      make(
        'venom/homoglyph',
        'error',
        subject,
        'Suspicious characters in package name',
        homo.reason,
      ),
      homo.reason,
    );
  }

  // --- Metadata-based checks ---
  if (meta) {
    for (const signal of assessMaintainerRisk(meta, options.now ? { now: options.now } : {})) {
      record(
        make('venom/maintainer-risk', signal.level, subject, signal.detail, signal.detail),
        signal.detail,
      );
    }
    const scriptSignals = inspectInstallScripts(meta.installScripts);
    for (const signal of scriptSignals) {
      const detail = `Install script (${signal.script}) ${signal.reasons.join('; ')}`;
      record(
        make('venom/install-script', 'error', subject, `Dangerous ${signal.script} script`, detail),
        detail,
      );
    }
    if (scriptSignals.length === 0 && meta.hasInstallScripts) {
      const detail = `Runs install scripts (${Object.keys(meta.installScripts ?? {}).join(', ')})`;
      record(
        make('venom/install-script-present', 'note', subject, 'Declares install scripts', detail),
        detail,
      );
    }
  }

  // --- Deep static analysis (download tarball, never execute) ---
  if (options.deep && meta) {
    const tarball = await adapter.fetchTarball(subject, ctx);
    if (tarball) {
      try {
        for (const sf of await scanSourceTree(tarball.extractedPath)) {
          const kinds = [...new Set(sf.astSignals.map((s) => s.kind))];
          const exfil = kinds.includes('env-access') && kinds.includes('network');
          const level: FindingLevel = exfil || sf.entropyHits.length > 0 ? 'warning' : 'note';
          const bits = [
            ...(kinds.length ? [kinds.join(', ')] : []),
            ...(sf.entropyHits.length ? [`${sf.entropyHits.length} high-entropy blob(s)`] : []),
          ];
          const detail = `${sf.file}: ${bits.join('; ')}`;
          record(
            make('venom/source-analysis', level, subject, `Suspicious code in ${sf.file}`, detail),
            detail,
          );
        }
      } finally {
        await tarball.dispose();
      }
    }
  }

  return { ref: subject, verdict: toVerdict(findings), reasons, findings };
}

export interface MaliciousScanResult {
  /** Packages that came back caution or flagged (clear packages are omitted). */
  assessments: PackageAssessment[];
  findings: Finding[];
}

export interface ScanMaliciousOptions {
  now?: Date;
  concurrency?: number;
  /**
   * Fetch registry metadata for every node (not just direct deps). Off by default
   * because it means one registry call per transitive package; name-based checks
   * (typosquat/homoglyph) still run across the whole tree regardless.
   */
  metadataForAll?: boolean;
}

/**
 * Whole-tree malicious scan (audit mode). Name-based checks run on every package;
 * metadata checks (maintainer risk, install scripts) run on direct dependencies by
 * default to bound network cost. Deep tarball analysis is reserved for the Bouncer.
 */
export async function scanMalicious(
  graph: DependencyGraph,
  ctx: ScanContext,
  options: ScanMaliciousOptions = {},
): Promise<MaliciousScanResult> {
  const nodes = [...graph.nodes.values()];
  const adapters = new Map<Ecosystem, EcosystemAdapter>();

  const results = await mapWithConcurrency(nodes, options.concurrency ?? 8, (node) => {
    let adapter = adapters.get(node.ref.ecosystem);
    if (!adapter) {
      adapter = adapterFor(node.ref.ecosystem);
      adapters.set(node.ref.ecosystem, adapter);
    }
    return assessPackage(adapter, node.ref, ctx, {
      deep: false,
      metadata: options.metadataForAll ? true : node.direct,
      ...(options.now ? { now: options.now } : {}),
    });
  });

  return {
    assessments: results.filter((r) => r.verdict !== 'clear'),
    findings: results.flatMap((r) => r.findings),
  };
}

/**
 * Bouncer mode (SPEC.md §6): assess a single candidate package *before* install.
 * Runs the full battery including deep tarball analysis by default.
 */
export async function checkCandidate(
  ecosystem: Ecosystem,
  name: string,
  ctx: ScanContext,
  options: { deep?: boolean; now?: Date } = {},
): Promise<PackageAssessment> {
  const adapter = adapterFor(ecosystem);
  const ref: PackageRef = { ecosystem, name, version: '' };
  return assessPackage(adapter, ref, ctx, {
    deep: options.deep ?? true,
    metadata: true,
    flagNotFound: true,
    ...(options.now ? { now: options.now } : {}),
  });
}

function adapterFor(ecosystem: Ecosystem): EcosystemAdapter {
  return ecosystem === 'pypi' ? new PypiAdapter() : new NpmAdapter();
}

function make(
  ruleId: string,
  level: FindingLevel,
  ref: PackageRef,
  title: string,
  message: string,
): Finding {
  return {
    ruleId,
    level,
    category: ruleId.includes('maintainer') ? 'maintainer-risk' : 'malicious',
    title,
    message,
    locations: [{ uri: toPurl(ref) }],
    fingerprint: `${ruleId}::${packageKey(ref)}`,
    relatedPackage: ref,
  };
}

function toVerdict(findings: Finding[]): BouncerVerdict {
  let worst = 0;
  for (const f of findings) worst = Math.max(worst, LEVEL_RANK[f.level]);
  if (worst >= LEVEL_RANK.error) return 'flagged';
  if (worst >= LEVEL_RANK.warning) return 'caution';
  return 'clear';
}
