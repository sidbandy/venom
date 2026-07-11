import type { InventorySummary } from '../inventory/build-graph';
import type { PackageAssessment } from '../malicious/assess';
import type { HealthComponent, HealthGrade, HealthScore } from '../types/health';
import type { Secret } from '../types/secret';
import type { UpdatePlanEntry } from '../types/update';
import type { Vulnerability } from '../types/vulnerability';

export interface HealthInputs {
  summary: InventorySummary;
  vulnerabilities: Vulnerability[];
  assessments: PackageAssessment[];
  secrets: Secret[];
  /** Optional: when present, dependency freshness contributes to the score. */
  updatePlan?: UpdatePlanEntry[];
}

export interface HealthScoreOptions {
  /** Timestamp to stamp; defaults to now (injected for deterministic tests). */
  now?: Date;
}

/**
 * Compute the composite Supply-Chain Health Score (SPEC.md §3.2, §5): a single
 * 0–100 number that makes Venom useful on every run. Each component is scored 0–100
 * in isolation (100 = healthy) then combined by weight. This is a pure function of
 * already-gathered module outputs — no network, no side effects.
 */
export function computeHealthScore(
  inputs: HealthInputs,
  options: HealthScoreOptions = {},
): HealthScore {
  const components: HealthComponent[] = [
    cveComponent(inputs.vulnerabilities),
    secretsComponent(inputs.secrets),
    maintainerComponent(inputs.assessments),
    depthComponent(inputs.summary),
  ];
  if (inputs.updatePlan) components.push(freshnessComponent(inputs.updatePlan));

  const totalWeight = components.reduce((sum, c) => sum + c.weight, 0);
  const composite = components.reduce((sum, c) => sum + c.score * c.weight, 0) / totalWeight;
  const score = Math.round(composite);

  return {
    score,
    grade: gradeFor(score),
    components,
    computedAt: (options.now ?? new Date()).toISOString(),
  };
}

function cveComponent(vulns: Vulnerability[]): HealthComponent {
  let penalty = 0;
  let critical = 0;
  let high = 0;
  for (const v of vulns) {
    if (v.severity === 'critical') {
      penalty += 25;
      critical++;
    } else if (v.severity === 'high') {
      penalty += 12;
      high++;
    } else if (v.severity === 'medium') penalty += 5;
    else if (v.severity === 'low') penalty += 1;
    if (v.knownExploited) penalty += 15;
  }
  return {
    id: 'cve-exposure',
    label: 'CVE exposure',
    score: clamp(100 - penalty),
    weight: 0.35,
    summary: vulns.length
      ? `${vulns.length} known ${vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} (${critical} critical, ${high} high)`
      : 'No known vulnerabilities',
  };
}

function secretsComponent(secrets: Secret[]): HealthComponent {
  let penalty = 0;
  let breached = 0;
  for (const s of secrets) {
    penalty += s.location.inHistory ? 15 : 40;
    if (s.breached) {
      penalty += 20;
      breached++;
    }
  }
  return {
    id: 'secrets-hygiene',
    label: 'Secrets hygiene',
    score: clamp(100 - penalty),
    weight: 0.25,
    summary: secrets.length
      ? `${secrets.length} leaked secret(s)${breached ? `, ${breached} breached` : ''}`
      : 'No leaked secrets',
  };
}

function maintainerComponent(assessments: PackageAssessment[]): HealthComponent {
  let penalty = 0;
  let flagged = 0;
  let caution = 0;
  for (const a of assessments) {
    if (a.verdict === 'flagged') {
      penalty += 20;
      flagged++;
    } else if (a.verdict === 'caution') {
      penalty += 6;
      caution++;
    }
  }
  return {
    id: 'maintainer-health',
    label: 'Package & maintainer health',
    score: clamp(100 - penalty),
    weight: 0.15,
    summary: assessments.length
      ? `${flagged} flagged, ${caution} caution among direct dependencies`
      : 'No package-risk signals',
  };
}

function freshnessComponent(plan: UpdatePlanEntry[]): HealthComponent {
  let penalty = 0;
  for (const e of plan) {
    penalty += e.tier === 'risky' ? 8 : e.tier === 'recommended' ? 5 : 1;
  }
  return {
    id: 'dependency-freshness',
    label: 'Dependency freshness',
    score: clamp(100 - penalty),
    weight: 0.15,
    summary: plan.length
      ? `${plan.length} outdated direct dependencies`
      : 'Dependencies up to date',
  };
}

function depthComponent(summary: InventorySummary): HealthComponent {
  const depthPenalty = Math.max(0, (summary.maxDepth - 4) * 8);
  const bloatPenalty = Math.max(0, (summary.total - 100) / 20);
  return {
    id: 'tree-depth',
    label: 'Dependency tree depth & size',
    score: clamp(100 - depthPenalty - bloatPenalty),
    weight: 0.1,
    summary: `${summary.total} packages, max depth ${summary.maxDepth}`,
  };
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function gradeFor(score: number): HealthGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
