import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/.next/**', '**/node_modules/**', 'python/**', '**/coverage/**', '**/*.cjs', 'apps/dashboard/next-env.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-console': ['warn', { allow: ['error', 'warn'] }],
    },
  },
  {
    files: ['**/*.test.ts', '**/scripts/**', '**/cli.ts', '**/bin/**'],
    rules: { 'no-console': 'off' },
  },
  {
    // Node ESM helper scripts (e.g. the dashboard's Playwright stub server) run under Node, not the browser.
    files: ['apps/dashboard/e2e/**/*.mjs'],
    languageOptions: { globals: { process: 'readonly', console: 'readonly' } },
    rules: { 'no-console': 'off' },
  },
);
