import eslint from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import globals from 'globals';

export default [
  eslint.configs.recommended,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      globals: {
        ...globals.browser,
        ...globals.node,
        chrome: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      // TypeScript-specific rules - warn for now to enable gradual cleanup
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-explicit-any': 'warn',

      // Turn off base rules that conflict with TS
      'no-unused-vars': 'off',
      'no-undef': 'off', // TypeScript handles this

      // General code quality
      'no-console': 'off', // Allow console for extension debugging
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },
  {
    // Test files - more lenient
    files: ['**/*.test.ts', '**/tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
  {
    ignores: [
      'dist/**',
      'dist-enterprise/**',
      'cli/dist/**',
      '.wrangler/**',
      'node_modules/**',
      'admin/**', // Separate monorepo with its own ESLint config
      'scripts/**', // Build scripts
      'website/**', // Marketing website
      'docs/**', // Documentation
      '*.js', // JS config files
      '*.mjs', // JS config files
      'vite.config.ts',
    ],
  },
];
