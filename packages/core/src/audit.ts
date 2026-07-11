import type { ScanContext } from './types/context';
import type { DependencyGraph } from './types/graph';
import type { Finding } from './types/finding';
import type { Vulnerability } from './types/vulnerability';
import type { Secret } from './types/secret';
import type { UpdatePlanEntry } from './types/update';
import type { HealthScore } from './types/health';
import { inventoryProject, summarizeGraph, type InventorySummary } from './inventory/index';
import { scanVulnerabilities } from './vulnerabilities/index';
import { scanMalicious, type PackageAssessment } from './malicious/index';
import { scanSecrets } from './secrets/index';
import { buildUpdatePlan } from './remediation/index';
import { computeHealthScore } from './health/index';

export interface AuditOptions {
  /** Scan git history for secrets (in addition to the working tree). Default true. */
  history?: boolean;
  /** Run HIBP breach checks on password-type secrets. Default true. */
  breachCheck?: boolean;
  /** Compute the tiered update plan (a network cost per direct dep). Default true. */
  updatePlan?: boolean;
}

export interface AuditResult {
  graph: DependencyGraph;
  summary: InventorySummary;
  vulnerabilities: Vulnerability[];
  assessments: PackageAssessment[];
  secrets: Secret[];
  updatePlan: UpdatePlanEntry[];
  healthScore: HealthScore;
  /** All findings from every module, aggregated (ready for SARIF). */
  findings: Finding[];
}

/**
 * Run the full Venom audit pipeline for a project (SPEC.md §9.3): inventory →
 * known vulns → malicious-package risk → secrets → update plan → composite Health
 * Score. This is the single orchestration every surface (CLI, CI action, plugin)
 * calls, so they all behave identically. Persistence of the score to history is
 * left to the caller (a side effect the engine doesn't own).
 */
export async function auditProject(
  ctx: ScanContext,
  options: AuditOptions = {},
): Promise<AuditResult> {
  const graph = await inventoryProject(ctx.projectRoot);
  const summary = summarizeGraph(graph);

  const { vulnerabilities, findings: vulnFindings } = await scanVulnerabilities(graph, ctx);
  const { assessments, findings: malFindings } = await scanMalicious(graph, ctx);
  // scanSecrets treats undefined history/breachCheck as its defaults (both true).
  const secretsOpts: { history?: boolean; breachCheck?: boolean } = {};
  if (options.history !== undefined) secretsOpts.history = options.history;
  if (options.breachCheck !== undefined) secretsOpts.breachCheck = options.breachCheck;
  const { secrets, findings: secretFindings } = await scanSecrets(
    ctx.projectRoot,
    ctx,
    secretsOpts,
  );

  const updatePlan =
    options.updatePlan === false ? [] : await buildUpdatePlan(graph, vulnerabilities, ctx);

  const healthScore = computeHealthScore({
    summary,
    vulnerabilities,
    assessments,
    secrets,
    updatePlan,
  });

  return {
    graph,
    summary,
    vulnerabilities,
    assessments,
    secrets,
    updatePlan,
    healthScore,
    findings: [...vulnFindings, ...malFindings, ...secretFindings],
  };
}
