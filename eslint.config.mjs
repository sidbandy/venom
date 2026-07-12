// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // demo/ holds intentional fixture projects (CommonJS sample apps), not product code.
    ignores: ['**/dist/**', '**/node_modules/**', '**/*.d.ts', 'demo/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': 'error',
      // Enforce the "engine is a library" boundary: the CLI/plugin/action may not
      // reach into @venom/core internals — only its public entrypoint.
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@venom/core/*', '@venom/core/dist/*'],
              message:
                'Import only from the @venom/core public API (its package root), never internal paths.',
            },
          ],
        },
      ],
    },
  },
);
