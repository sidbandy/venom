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
  generateSbom,
  NoSupportedLockfileError,
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

        for (const f of findings.slice(0, 20)) {
          const mark = f.level === 'error' ? '✖' : f.level === 'warning' ? '▲' : '·';
          console.log(`\n  ${mark} ${f.title}`);
          if (f.remediation) console.log(`      ${f.remediation}`);
        }
        if (findings.length > 20) console.log(`\n  … and ${findings.length - 20} more.`);
        console.log('\n(Modules 3–5 land next; this reports Modules 1–2.)\n');
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
  .command('check <package>')
  .description('Bouncer check: evaluate a package before installing it')
  .action((pkg: string) => {
    console.log(`venom check ${pkg} — not yet implemented`);
  });

program.parseAsync();

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
