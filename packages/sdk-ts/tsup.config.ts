import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'fetch/index': 'src/fetch/index.ts',
    'verifier/index': 'src/verifier/index.ts',
    'client/index': 'src/client/index.ts',
    'ids/index': 'src/ids/index.ts',
    'merkle/index': 'src/merkle/index.ts',
    'estimate/index': 'src/estimate/index.ts',
    'hash/index': 'src/hash/index.ts',
    'certificate/index': 'src/certificate/index.ts',
    'identity/index': 'src/identity/index.ts',
    'conformance/cli': 'src/conformance/cli.ts',
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
  external: [
    '@noble/hashes',
    '@noble/curves',
    '@noble/ed25519',
    '@noble/ciphers',
    'cbor2',
    'age-encryption',
    'hash-wasm',
    'zod',
  ],
  noExternal: ['@cardanowall/crypto-core', '@cardanowall/poe-standard'],
});
