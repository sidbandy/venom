import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    // Run tests against core's TypeScript source (no build step needed for TDD),
    // while still importing it via its public package name everywhere else.
    alias: {
      '@venom/core': resolve(__dirname, 'packages/core/src/index.ts'),
    },
  },
});
