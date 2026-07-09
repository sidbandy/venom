#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import {
  VERSION,
  inventoryProject,
  summarizeGraph,
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
  .action(async (dir: string) => {
    await withProject(dir, async (projectRoot) => {
      const graph = await inventoryProject(projectRoot);
      const s = summarizeGraph(graph);
      const eco = s.ecosystems.map((e) => `${e} ${s.byEcosystem[e] ?? 0}`).join(', ');
      console.log(
        `\nVenom audit — ${graph.root.name}${graph.root.version ? `@${graph.root.version}` : ''}`,
      );
      console.log(`  Dependencies : ${s.total} (${s.direct} direct, ${s.transitive} transitive)`);
      console.log(`  Ecosystems   : ${eco}`);
      console.log(`  Max depth    : ${s.maxDepth}`);
      console.log('\n(Modules 2–5 land next; this reports the Module 1 inventory.)\n');
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
