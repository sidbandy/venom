import semver from 'semver';
import type { ScanContext } from '../types/context';
import type { Ecosystem, PackageRef } from '../types/ecosystem';
import { packageKey } from '../types/ecosystem';
import type { DependencyGraph } from '../types/graph';
import type { Finding, FindingLevel } from '../types/finding';
import type { CvssScore, VulnSeverity, Vulnerability } from '../types/vulnerability';
import { toPurl, normalizePypiName } from '../inventory/purl';
import { cvssFromVector, severityFromLabel, severityFromScore } from './cvss';
import { KevCatalog } from './kev';
import { OsvClient, osvEcosystem, type OsvVulnerability } from './osv';

export interface VulnerabilityScanResult {
  vulnerabilities: Vulnerability[];
  findings: Finding[];
}

const SEVERITY_RANK: Record<VulnSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  none: 1,
  unknown: 0,
};

/**
 * Module 2 entry point: check every package in the graph against OSV.dev,
 * cross-reference CISA KEV, and produce both structured {@link Vulnerability}
 * records and SARIF-ready {@link Finding}s. This is the module that fires on
 * nearly every real project (SPEC.md §4 M2).
 */
export async function scanVulnerabilities(
  graph: DependencyGraph,
  ctx: ScanContext,
): Promise<VulnerabilityScanResult> {
  const refs = [...graph.nodes.values()].map((n) => n.ref);
  const osv = new OsvClient();

  const idsByPackage = await osv.idsForPackages(refs, ctx);
  const kev = await new KevCatalog().load(ctx);

  const uniqueIds = new Set<string>();
  for (const ids of idsByPackage.values()) for (const id of ids) uniqueIds.add(id);

  const details = new Map<string, OsvVulnerability>();
  for (const id of uniqueIds) {
    const vuln = await osv.getVuln(id, ctx);
    if (vuln) details.set(id, vuln);
  }

  const vulnerabilities: Vulnerability[] = [];
  for (const ref of refs) {
    for (const id of idsByPackage.get(packageKey(ref)) ?? []) {
      const osvVuln = details.get(id);
      // Skip advisories that OSV has retracted.
      if (osvVuln && !osvVuln.withdrawn) vulnerabilities.push(toVulnerability(osvVuln, ref, kev));
    }
  }

  vulnerabilities.sort(compareBySeverityThenPackage);
  return { vulnerabilities, findings: vulnerabilities.map(toFinding) };
}

/** Roll vulnerabilities up into headline counts for the CLI and Health Score. */
export function summarizeVulnerabilities(vulns: Vulnerability[]): {
  total: number;
  bySeverity: Record<VulnSeverity, number>;
  knownExploited: number;
} {
  const bySeverity: Record<VulnSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
    unknown: 0,
  };
  let knownExploited = 0;
  for (const v of vulns) {
    bySeverity[v.severity] += 1;
    if (v.knownExploited) knownExploited += 1;
  }
  return { total: vulns.length, bySeverity, knownExploited };
}

function toVulnerability(osv: OsvVulnerability, ref: PackageRef, kev: Set<string>): Vulnerability {
  const aliases = osv.aliases ?? [];
  const cvss = pickCvss(osv.severity);
  // OSV aggregates the npm/PyPI *malware* advisories as `MAL-…`; such a package is
  // known malware, not merely buggy — always critical.
  const malicious =
    osv.id.startsWith('MAL-') ||
    aliases.some((a) => a.startsWith('MAL-')) ||
    Boolean(osv.database_specific?.malicious);
  const severity = malicious
    ? 'critical'
    : cvss
      ? severityFromScore(cvss.baseScore)
      : severityFromLabel(osv.database_specific?.severity);
  const knownExploited = [osv.id, ...aliases].some((id) => kev.has(id));

  return {
    id: osv.id,
    aliases,
    ...(osv.summary ? { summary: osv.summary } : {}),
    ...(osv.details ? { details: osv.details } : {}),
    ...(cvss ? { cvss } : {}),
    severity,
    knownExploited,
    ...(malicious ? { malicious: true } : {}),
    affected: ref,
    fixedVersions: extractFixedVersions(osv, ref),
    references: (osv.references ?? []).map((r) => r.url),
    ...(osv.published ? { published: osv.published } : {}),
    ...(osv.modified ? { modified: osv.modified } : {}),
  };
}

function toFinding(vuln: Vulnerability): Finding {
  const cveOrId = vuln.aliases.find((a) => a.startsWith('CVE-')) ?? vuln.id;
  const pkg = `${vuln.affected.name}@${vuln.affected.version}`;
  const lowestFixed = lowestVersion(vuln.fixedVersions, vuln.affected.ecosystem);

  // A known-malicious package is not a CVE to patch — it's malware to remove now.
  if (vuln.malicious) {
    return {
      ruleId: 'venom/malicious-package',
      level: 'error',
      category: 'malicious',
      title: `KNOWN MALICIOUS PACKAGE: ${pkg}`,
      message: `${vuln.summary ?? 'This package is flagged as malware'} (OSV ${vuln.id}). Remove it immediately and rotate any exposed credentials.`,
      locations: [{ uri: toPurl(vuln.affected) }],
      fingerprint: `malicious::${packageKey(vuln.affected)}`,
      relatedPackage: vuln.affected,
      remediation: `Remove ${vuln.affected.name} immediately; it is known malware.`,
      properties: {
        osvId: vuln.id,
        aliases: vuln.aliases,
        malicious: true,
        references: vuln.references,
      },
    };
  }

  const level = findingLevel(vuln);
  const kevNote = vuln.knownExploited ? ' [CISA KEV — actively exploited in the wild]' : '';
  const cvssNote = vuln.cvss ? ` (CVSS ${vuln.cvss.baseScore})` : '';

  return {
    ruleId: `venom/${cveOrId}`,
    level,
    category: 'vulnerability',
    title: `${cveOrId} in ${pkg}`,
    message: `${vuln.summary ?? cveOrId}${kevNote}. Severity: ${vuln.severity}${cvssNote}.`,
    locations: [{ uri: toPurl(vuln.affected) }],
    fingerprint: `${cveOrId}::${packageKey(vuln.affected)}`,
    relatedPackage: vuln.affected,
    remediation: lowestFixed
      ? `Upgrade ${vuln.affected.name} to ${lowestFixed} or later.`
      : 'No fixed version is available yet.',
    properties: {
      osvId: vuln.id,
      aliases: vuln.aliases,
      severity: vuln.severity,
      knownExploited: vuln.knownExploited,
      ...(vuln.cvss ? { cvssScore: vuln.cvss.baseScore, cvssVector: vuln.cvss.vectorString } : {}),
      fixedVersions: vuln.fixedVersions,
      references: vuln.references,
    },
  };
}

function findingLevel(vuln: Vulnerability): FindingLevel {
  if (vuln.knownExploited || vuln.severity === 'critical' || vuln.severity === 'high') {
    return 'error';
  }
  if (vuln.severity === 'medium') return 'warning';
  return 'note';
}

/** Prefer the highest-scoring CVSS vector we can numerically evaluate. */
function pickCvss(severities: OsvVulnerability['severity']): CvssScore | undefined {
  if (!severities) return undefined;
  let best: CvssScore | undefined;
  for (const s of severities) {
    const c = cvssFromVector(s.score);
    if (c && (!best || c.baseScore > best.baseScore)) best = c;
  }
  return best;
}

function extractFixedVersions(osv: OsvVulnerability, ref: PackageRef): string[] {
  const fixed = new Set<string>();
  for (const aff of osv.affected ?? []) {
    if (!affectedMatches(ref, aff.package)) continue;
    for (const range of aff.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed];
}

function affectedMatches(
  ref: PackageRef,
  pkg: { ecosystem: string; name: string } | undefined,
): boolean {
  if (!pkg) return false;
  if (osvEcosystem(ref.ecosystem) !== pkg.ecosystem) return false;
  return ref.ecosystem === 'pypi'
    ? normalizePypiName(ref.name) === normalizePypiName(pkg.name)
    : ref.name === pkg.name;
}

function lowestVersion(versions: string[], ecosystem: Ecosystem): string | undefined {
  if (versions.length === 0) return undefined;
  if (ecosystem === 'npm' && versions.every((v) => semver.valid(v))) {
    return [...versions].sort(semver.compare)[0];
  }
  return [...versions].sort()[0];
}

function compareBySeverityThenPackage(a: Vulnerability, b: Vulnerability): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return packageKey(a.affected).localeCompare(packageKey(b.affected));
}
