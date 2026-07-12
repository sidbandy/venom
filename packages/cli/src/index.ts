#!/usr/bin/env node

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Command } from 'commander';
import {
  VERSION,
  createScanContext,
  auditProject,
  inventoryProject,
  summarizeVulnerabilities,
  summarizeSecrets,
  checkCandidate,
  scanVulnerabilities,
  scanSecrets,
  generateSbom,
  generateSarif,
  buildUpdatePlan,
  applyNpmUpdates,
  detectUnusedDependencies,
  checkLicenses,
  loadPolicy,
  evaluatePolicy,
  STARTER_POLICY,
  ScoreHistoryStore,
  NoSupportedLockfileError,
  type AuditResult,
  type Policy,
  type ScanContextHandle,
  type ScoreRecord,
  type Ecosystem,
  type PackageAssessment,
  type SbomFormat,
} from '@venom/core';

const program = new Command();

program
  .name('venom')
  .description('Supply chain security & health platform — bouncer, not janitor.')
  .version(VERSION);

program
  .command('audit')
  .description('Run a full audit of the current project')
  .argument('[dir]', 'project directory', '.')
  .option('--offline', 'do not make any network calls; use cached/bundled data only', false)
  .option('--sarif <file>', 'write all findings as SARIF 2.1.0 to a file')
  .action(async (dir: string, opts: { offline: boolean; sarif?: string }) => {
    await withProject(dir, async (projectRoot) => {
      const ctx = await makeContext(projectRoot, opts.offline);
      try {
        const result = await auditProject(ctx);
        recordScore(ctx, result);

        const { summary: inv, assessments, secrets, healthScore: h } = result;
        const v = summarizeVulnerabilities(result.vulnerabilities);
        const sec = summarizeSecrets(secrets);
        const eco = inv.ecosystems.map((e) => `${e} ${inv.byEcosystem[e] ?? 0}`).join(', ');
        const rootLabel = `${result.graph.root.name}${result.graph.root.version ? `@${result.graph.root.version}` : ''}`;

        console.log(`\nVenom audit — ${rootLabel}`);
        console.log(`  Health Score : ${h.score}/100 (${h.grade})`);
        console.log(
          `  Dependencies : ${inv.total} (${inv.direct} direct, ${inv.transitive} transitive) · ${eco} · max depth ${inv.maxDepth}`,
        );
        console.log(
          `  Vulnerabilities : ${v.total}` +
            (v.total
              ? ` (${v.bySeverity.critical} critical, ${v.bySeverity.high} high, ` +
                `${v.bySeverity.medium} medium, ${v.bySeverity.low} low` +
                (v.knownExploited ? `; ${v.knownExploited} actively exploited` : '') +
                `) — ${result.reachableVulnerabilities.length} reachable from your code`
              : ''),
        );
        const flagged = assessments.filter((a) => a.verdict === 'flagged').length;
        console.log(
          `  Package risk : ${assessments.length} of concern` +
            (assessments.length ? ` (${flagged} flagged)` : ''),
        );
        console.log(
          `  Secrets : ${sec.total}` +
            (sec.total
              ? ` (${sec.inWorkingTree} in tree, ${sec.inHistoryOnly} history-only` +
                (sec.breached ? `, ${sec.breached} breached` : '') +
                ')'
              : ''),
        );
        const licenseIssues = result.findings.filter((f) => f.category === 'license').length;
        if (result.unusedDependencies.length || licenseIssues) {
          console.log(
            `  Hygiene : ${result.unusedDependencies.length} unused dep(s), ${licenseIssues} license issue(s)`,
          );
        }

        // Reachable CVEs first — those are the ones that can actually hurt you.
        const vulnFindings = result.findings
          .filter((f) => f.category === 'vulnerability')
          .sort((a, b) => Number(b.properties?.reachable) - Number(a.properties?.reachable));
        for (const f of vulnFindings.slice(0, 12)) {
          const mark = f.level === 'error' ? '✖' : f.level === 'warning' ? '▲' : '·';
          const reach = f.properties?.reachable ? ' ⟶ reachable' : '';
          console.log(`\n  ${mark} ${f.title}${reach}`);
          if (f.remediation) console.log(`      ${f.remediation}`);
        }
        for (const a of assessments.slice(0, 8)) {
          console.log(`\n  ${verdictMark(a)} ${a.ref.name}@${a.ref.version}`);
          for (const reason of a.reasons.slice(0, 3)) console.log(`      → ${reason}`);
        }
        for (const s of secrets.slice(0, 8)) {
          const loc = s.location.inHistory ? `${s.location.file} (git history)` : s.location.file;
          console.log(`\n  🔑 ${s.description} — ${loc}`);
        }

        if (opts.sarif) {
          writeFileSync(
            resolve(opts.sarif),
            generateSarif(result.findings, { toolVersion: VERSION }),
          );
          console.log(`\n  SARIF: wrote ${result.findings.length} findings to ${opts.sarif}`);
        }
        console.log('\n(Run `venom fix` for an update plan or `venom score` for the trend.)\n');
      } finally {
        ctx.dispose();
      }
    });
  });

program
  .command('score')
  .description('Print the supply-chain health score, its breakdown, and trend')
  .argument('[dir]', 'project directory', '.')
  .option('--offline', 'do not make any network calls', false)
  .action(async (dir: string, opts: { offline: boolean }) => {
    await withProject(dir, async (projectRoot) => {
      const ctx = createScanContext({ projectRoot, offline: opts.offline });
      try {
        const result = await auditProject(ctx);
        const trend = recordScore(ctx, result);
        const h = result.healthScore;
        console.log(`\nSupply Chain Health: ${h.score}/100 (grade ${h.grade})\n`);
        for (const c of h.components) {
          console.log(
            `  ${bar(c.score)} ${c.label.padEnd(30)} ${String(c.score).padStart(3)}/100  ${c.summary}`,
          );
        }
        if (trend.length > 1) {
          console.log(`\n  Trend: ${trend.map((r) => r.score).join(' → ')}`);
        }
        console.log('');
      } finally {
        ctx.dispose();
      }
    });
  });

program
  .command('sbom')
  .description('Generate a Software Bill of Materials (SPDX or CycloneDX)')
  .argument('[dir]', 'project directory', '.')
  .option('-f, --format <format>', 'spdx | cyclonedx', 'cyclonedx')
  .option('-o, --output <file>', 'write to a file instead of stdout')
  .action(async (dir: string, opts: { format: string; output?: string }) => {
    const format = opts.format.toLowerCase();
    if (format !== 'spdx' && format !== 'cyclonedx') {
      console.error(`Unknown SBOM format "${opts.format}". Use "spdx" or "cyclonedx".`);
      process.exitCode = 2;
      return;
    }
    await withProject(dir, async (projectRoot) => {
      const graph = await inventoryProject(projectRoot);
      const output = generateSbom(graph, format as SbomFormat, { toolVersion: VERSION });
      if (opts.output) {
        writeFileSync(resolve(opts.output), output);
        console.error(
          `Wrote ${format.toUpperCase()} SBOM for ${graph.nodes.size} packages to ${opts.output}`,
        );
      } else {
        console.log(output);
      }
    });
  });

program
  .command('fix')
  .description('Plan and optionally apply dependency updates (safe / recommended / risky)')
  .argument('[dir]', 'project directory', '.')
  .option('--safe', 'restrict to the safe (patch-level, non-breaking) tier')
  .option('--apply', 'write the updates to package.json (default is a dry run)')
  .option('--offline', 'do not make any network calls', false)
  .action(async (dir: string, opts: { safe?: boolean; apply?: boolean; offline: boolean }) => {
    await withProject(dir, async (projectRoot) => {
      const ctx = createScanContext({ projectRoot, offline: opts.offline });
      try {
        const graph = await inventoryProject(projectRoot);
        const { vulnerabilities } = await scanVulnerabilities(graph, ctx);
        const plan = await buildUpdatePlan(graph, vulnerabilities, ctx);
        const shown = opts.safe ? plan.filter((e) => e.tier === 'safe') : plan;

        if (shown.length === 0) {
          console.log(
            opts.safe ? 'No safe updates available.' : 'All direct dependencies are current.',
          );
          return;
        }

        for (const tier of ['safe', 'recommended', 'risky'] as const) {
          const group = shown.filter((e) => e.tier === tier);
          if (group.length === 0) continue;
          console.log(`\n${tierLabel(tier)}`);
          for (const e of group) {
            console.log(`  ${e.current.name}  ${e.current.version} → ${e.targetVersion}`);
            console.log(`     ${e.reason}`);
          }
        }

        if (opts.apply) {
          const applied = await applyNpmUpdates(
            projectRoot,
            opts.safe ? shown : plan.filter((e) => e.tier === 'safe'),
          );
          if (applied.length > 0) {
            console.log(
              `\nApplied ${applied.length} update(s) to package.json. Run \`npm install\` to sync.`,
            );
          } else {
            console.log('\nNothing applied (only safe-tier npm updates are auto-applied).');
          }
        } else {
          console.log('\n(dry run — re-run with --apply to write safe updates to package.json)');
        }
      } finally {
        ctx.dispose();
      }
    });
  });

program
  .command('unused')
  .description('List declared-but-unused production dependencies')
  .argument('[dir]', 'project directory', '.')
  .action(async (dir: string) => {
    await withProject(dir, async (projectRoot) => {
      const { unused } = await detectUnusedDependencies(projectRoot);
      if (unused.length === 0) {
        console.log('No unused production dependencies found.');
        return;
      }
      console.log(`${unused.length} unused production dependencies:\n`);
      for (const name of unused) console.log(`  · ${name}`);
      process.exitCode = 1;
    });
  });

program
  .command('licenses')
  .description('License compliance report')
  .argument('[dir]', 'project directory', '.')
  .action(async (dir: string) => {
    await withProject(dir, async (projectRoot) => {
      const graph = await inventoryProject(projectRoot);
      const projectLicense = await readProjectLicense(projectRoot);
      const { findings, byLicense } = await checkLicenses(
        projectRoot,
        graph,
        projectLicense ? { projectLicense } : {},
      );
      console.log('\nLicense summary:');
      for (const [license, count] of Object.entries(byLicense).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${String(count).padStart(4)}  ${license}`);
      }
      if (findings.length === 0) {
        console.log('\nNo license conflicts or denials.');
        return;
      }
      console.log(`\n${findings.length} license issue(s):`);
      for (const f of findings) {
        const mark = f.level === 'error' ? '✖' : f.level === 'warning' ? '▲' : '·';
        console.log(`  ${mark} ${f.message}`);
      }
      process.exitCode = 1;
    });
  });

program
  .command('secrets')
  .description('Scan the working tree and full git history for leaked credentials')
  .argument('[dir]', 'project directory', '.')
  .option('--no-history', 'scan only the working tree, not git history')
  .option('--no-breach-check', 'do not check discovered passwords against Have I Been Pwned')
  .option('--offline', 'do not make any network calls', false)
  .action(
    async (dir: string, opts: { history: boolean; breachCheck: boolean; offline: boolean }) => {
      await withProject(dir, async (projectRoot) => {
        const ctx = createScanContext({ projectRoot, offline: opts.offline });
        try {
          const { secrets } = await scanSecrets(projectRoot, ctx, {
            history: opts.history,
            breachCheck: opts.breachCheck,
          });
          const sec = summarizeSecrets(secrets);
          if (sec.total === 0) {
            console.log('No secrets found in the working tree or git history.');
            return;
          }
          console.log(
            `Found ${sec.total} secret(s): ${sec.inWorkingTree} in the working tree, ` +
              `${sec.inHistoryOnly} history-only` +
              (sec.breached ? `, ${sec.breached} known-breached` : ''),
          );
          for (const s of secrets) {
            const loc = s.location.inHistory
              ? `${s.location.file}:${s.location.line ?? '?'} (history, commit ${s.location.commit?.slice(0, 8)})`
              : `${s.location.file}:${s.location.line ?? '?'}`;
            console.log(`\n  🔑 ${s.description}`);
            console.log(`     ${loc}`);
            console.log(
              `     ${s.preview}${s.breached ? ` — found in ${s.breachCount} breaches` : ''}`,
            );
          }
          process.exitCode = 1;
        } finally {
          ctx.dispose();
        }
      });
    },
  );

program
  .command('ci')
  .description('CI mode: enforce .venom.yml policy, emit SARIF, exit non-zero on violations')
  .argument('[dir]', 'project directory', '.')
  .option('--sarif <file>', 'SARIF output path', 'venom.sarif')
  .option('--offline', 'do not make any network calls', false)
  .action(async (dir: string, opts: { sarif: string; offline: boolean }) => {
    await withProject(dir, async (projectRoot) => {
      const policy = (await loadPolicy(projectRoot)) ?? DEFAULT_CI_POLICY;
      const ctx = createScanContext({ projectRoot, offline: opts.offline, policy });
      try {
        const result = await auditProject(ctx);
        recordScore(ctx, result);
        writeFileSync(
          resolve(opts.sarif),
          generateSarif(result.findings, { toolVersion: VERSION }),
        );

        const h = result.healthScore;
        console.log(
          `Venom CI — Health ${h.score}/100 (${h.grade}), ${result.findings.length} findings. SARIF → ${opts.sarif}`,
        );
        const evaluation = evaluatePolicy(result, policy);
        for (const w of evaluation.warnings) console.log(`  ⚠️  ${w}`);
        if (evaluation.passed) {
          console.log('\n✅ Policy check passed.');
        } else {
          console.log('\n🚫 Policy violations:');
          for (const v of evaluation.violations) console.log(`  ✖ ${v}`);
          process.exitCode = 1;
        }
      } finally {
        ctx.dispose();
      }
    });
  });

program
  .command('init')
  .description('Generate a starter .venom.yml policy file')
  .option('--hook', 'also install a git pre-commit hook that blocks commits containing secrets')
  .action((opts: { hook?: boolean }) => {
    const cwd = process.cwd();
    const policyPath = join(cwd, '.venom.yml');
    if (existsSync(policyPath)) {
      console.error('.venom.yml already exists — leaving it untouched.');
    } else {
      writeFileSync(policyPath, STARTER_POLICY);
      console.log('Wrote .venom.yml');
    }
    if (opts.hook) installPreCommitHook(cwd);
  });

program
  .command('check <package>')
  .description('Bouncer check: evaluate a package before installing it')
  .option('-e, --ecosystem <ecosystem>', 'npm | pypi', 'npm')
  .option('--no-deep', 'skip downloading and statically analyzing the package tarball')
  .option('--offline', 'do not make any network calls', false)
  .action(async (pkg: string, opts: { ecosystem: string; deep: boolean; offline: boolean }) => {
    const ecosystem: Ecosystem = opts.ecosystem === 'pypi' ? 'pypi' : 'npm';
    const ctx = createScanContext({ projectRoot: process.cwd(), offline: opts.offline });
    try {
      const assessment = await checkCandidate(ecosystem, pkg, ctx, { deep: opts.deep });
      printAssessment(assessment);
      process.exitCode = assessment.verdict === 'flagged' ? 1 : 0;
    } finally {
      ctx.dispose();
    }
  });

program.parseAsync();

function verdictMark(a: PackageAssessment): string {
  return a.verdict === 'flagged' ? '🚫' : a.verdict === 'caution' ? '⚠️ ' : '✅';
}

function tierLabel(tier: 'safe' | 'recommended' | 'risky'): string {
  return tier === 'safe'
    ? '✅ Safe (patch, non-breaking)'
    : tier === 'recommended'
      ? '▲ Recommended (minor)'
      : '🚫 Risky (major, likely breaking)';
}

/** Persist this run's score to local history and return the recent trend (oldest→newest). */
function recordScore(ctx: ScanContextHandle, result: AuditResult): ScoreRecord[] {
  const store = new ScoreHistoryStore(join(ctx.config.dataDir, 'history.db'));
  try {
    store.record({
      timestamp: result.healthScore.computedAt,
      score: result.healthScore.score,
      grade: result.healthScore.grade,
      cveCount: result.vulnerabilities.length,
      secretCount: result.secrets.length,
    });
    return store.recent(10).reverse();
  } finally {
    store.close();
  }
}

function bar(score: number): string {
  return '█'.repeat(Math.round(score / 10)).padEnd(10, '░');
}

/** A sensible default policy for `venom ci` when the project has no .venom.yml. */
const DEFAULT_CI_POLICY: Policy = {
  blockOnSecrets: true,
  blockOnKev: true,
  maxCvssSeverity: 9.0,
  licenseDenylist: ['AGPL-3.0'],
};

/** Build a scan context with the project's `.venom.yml` policy loaded in. */
async function makeContext(projectRoot: string, offline: boolean): Promise<ScanContextHandle> {
  const policy = await loadPolicy(projectRoot);
  return createScanContext({ projectRoot, offline, ...(policy ? { policy } : {}) });
}

function installPreCommitHook(cwd: string): void {
  if (!existsSync(join(cwd, '.git'))) {
    console.error('Not a git repository — skipping pre-commit hook install.');
    return;
  }
  const hookDir = join(cwd, '.git', 'hooks');
  mkdirSync(hookDir, { recursive: true });
  const script = `#!/bin/sh
# Venom pre-commit hook — block commits that introduce secrets.
venom secrets --no-history . || {
  echo "Venom blocked the commit: secrets detected. Fix them, or bypass with 'git commit --no-verify'."
  exit 1
}
`;
  writeFileSync(join(hookDir, 'pre-commit'), script, { mode: 0o755 });
  console.log('Installed .git/hooks/pre-commit');
}

async function readProjectLicense(projectRoot: string): Promise<string | undefined> {
  try {
    const pkg = JSON.parse(await readFile(join(projectRoot, 'package.json'), 'utf8')) as {
      license?: unknown;
    };
    return typeof pkg.license === 'string' ? pkg.license : undefined;
  } catch {
    return undefined;
  }
}

/** Render a Bouncer assessment, verdict-first, per SPEC.md §6.1. */
function printAssessment(a: PackageAssessment): void {
  const label =
    a.verdict === 'flagged' ? '🚫 Flagged' : a.verdict === 'caution' ? '⚠️  Caution' : '✅ Clear';
  const name = `${a.ref.name}${a.ref.version ? `@${a.ref.version}` : ''}`;
  console.log(`\n${label}      ${name}`);
  if (a.reasons.length === 0) {
    console.log('   → No risk signals detected');
  } else {
    for (const reason of a.reasons) console.log(`   → ${reason}`);
  }
  console.log('');
}

/** Run an action against a resolved project root with consistent error handling. */
async function withProject(
  dir: string,
  action: (projectRoot: string) => Promise<void>,
): Promise<void> {
  const projectRoot = resolve(dir);
  try {
    await action(projectRoot);
  } catch (err) {
    if (err instanceof NoSupportedLockfileError) {
      console.error(err.message);
      process.exitCode = 1;
      return;
    }
    throw err;
  }
}
