import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    schema: 'src/schema.ts',
    encoder: 'src/encoder.ts',
    validator: 'src/validator.ts',
    'error-codes': 'src/error-codes.ts',
  },
  format: ['esm', 'cjs'],
  target: 'es2024',
  platform: 'neutral',
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  dts: {
    compilerOptions: {
      ignoreDeprecations: '6.0',
    },
  },
  shims: false,
  external: ['zod'],
  noExternal: ['@cardanowall/crypto-core'],
});
