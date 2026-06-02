import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    hash: 'src/hash/index.ts',
    kdf: 'src/kdf/index.ts',
    sig: 'src/sig/index.ts',
    kem: 'src/kem/index.ts',
    aead: 'src/aead/index.ts',
    util: 'src/util/index.ts',
    cbor: 'src/cbor/index.ts',
    cose: 'src/cose/index.ts',
    'seed-derive': 'src/seed-derive/index.ts',
    'sealed-poe': 'src/sealed-poe/index.ts',
    merkle: 'src/merkle/index.ts',
    recipient: 'src/recipient/index.ts',
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
    '@noble/ciphers',
    '@noble/curves',
    '@noble/ed25519',
    '@noble/hashes',
    '@noble/post-quantum',
    'cbor2',
    'hash-wasm',
  ],
});
