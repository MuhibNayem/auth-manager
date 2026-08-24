module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    // The library entry (src/index.tsx) intentionally exports components,
    // hooks and stores together, so the react-refresh purity rule is off.
    'react-refresh/only-export-components': 'off',
    // The admin API is loosely typed at the boundary (FastAPI JSON);
    // explicit `any` at those seams is pragmatic.
    '@typescript-eslint/no-explicit-any': 'off',
  },
};
