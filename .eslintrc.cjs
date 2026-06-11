/* eslint config for eslint 8 + @typescript-eslint 6 (legacy .eslintrc) */
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  env: {
    es2022: true,
    node: true,
    browser: true,
  },
  ignorePatterns: ['dist/', 'node_modules/', 'coverage/', 'tests/', '*.cjs'],
  rules: {
    // The SDK deliberately uses `any` at a handful of wire-format boundaries
    // (CometBFT JSON, untyped server payloads); flag explicit `any` as a
    // warning rather than failing the lint, and don't error on inferred-any.
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': [
      'error',
      { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
    ],
    // `namespace`/`module` are used intentionally for grouped type exports.
    '@typescript-eslint/no-namespace': 'off',
    // Empty interfaces appear as extension points in the public type surface.
    '@typescript-eslint/no-empty-interface': 'off',
    'no-empty': ['error', { allowEmptyCatch: true }],
  },
};
