#!/usr/bin/env node

import { Command } from 'commander';

const program = new Command();

program
  .name('venom')
  .description('Supply chain security & health platform')
  .version('0.1.0');

program
  .command('audit')
  .description('Run a full audit of the current project')
  .action(() => {
    console.log('venom audit — not yet implemented');
  });

program
  .command('check <package>')
  .description('Bouncer check: evaluate a package before installing it')
  .action((pkg: string) => {
    console.log(`venom check ${pkg} — not yet implemented`);
  });

program.parse();
