#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import {
  VERSION,
  createScanContext,
  inventoryProject,
  summarizeGraph,
  scanVulnerabilities,
  summarizeVulnerabilities,
  scanMalicious,
  checkCandidate,
  scanSecrets,
  summarizeSecrets,
  generateSbom,
  NoSupportedLockfileError,
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
  .action(async (dir: string, opts: { offline: boolean }) => {
    await withProject(dir, async (projectRoot) => {
      const ctx = createScanContext({ projectRoot, offline: opts.offline });
      try {
        const graph = await inventoryProject(projectRoot);
        const inv = summarizeGraph(graph);
        const eco = inv.ecosystems.map((e) => `${e} ${inv.byEcosystem[e] ?? 0}`).join(', ');

        const { vulnerabilities, findings } = await scanVulnerabilities(graph, ctx);
        const v = summarizeVulnerabilities(vulnerabilities);
        const { assessments } = await scanMalicious(graph, ctx);
        const { secrets } = await scanSecrets(projectRoot, ctx);
        const sec = summarizeSecrets(secrets);

        console.log(
          `\nVenom audit — ${graph.root.name}${graph.root.version ? `@${graph.root.version}` : ''}`,
        );
        console.log(
          `  Dependencies : ${inv.total} (${inv.direct} direct, ${inv.transitive} transitive)`,
        );
        console.log(`  Ecosystems   : ${eco}`);
        console.log(`  Max depth    : ${inv.maxDepth}`);
        console.log(
          `  Vulnerabilities : ${v.total}` +
            (v.total
              ? ` (${v.bySeverity.critical} critical, ${v.bySeverity.high} high, ` +
                `${v.bySeverity.medium} medium, ${v.bySeverity.low} low` +
                (v.knownExploited ? `; ${v.knownExploited} actively exploited` : '') +
                ')'
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

        for (const f of findings.slice(0, 15)) {
          const mark = f.level === 'error' ? '✖' : f.level === 'warning' ? '▲' : '·';
          console.log(`\n  ${mark} ${f.title}`);
          if (f.remediation) console.log(`      ${f.remediation}`);
        }
        if (findings.length > 15)
          console.log(`\n  … and ${findings.length - 15} more CVE findings.`);

        for (const a of assessments.slice(0, 10)) {
          console.log(`\n  ${verdictMark(a)} ${a.ref.name}@${a.ref.version}`);
          for (const reason of a.reasons.slice(0, 3)) console.log(`      → ${reason}`);
        }

        for (const s of secrets.slice(0, 10)) {
          const loc = s.location.inHistory ? `${s.location.file} (git history)` : s.location.file;
          console.log(`\n  🔑 ${s.description} — ${loc}`);
          console.log(
            `      ${s.preview}${s.breached ? ` (found in ${s.breachCount} breaches)` : ''}`,
          );
        }
        console.log('\n(Module 5 lands next; this reports Modules 1–4.)\n');
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
