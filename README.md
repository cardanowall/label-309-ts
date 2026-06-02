# CIP-309 TypeScript SDKs

TypeScript reference implementation of [**CIP-309**](https://github.com/cardanowall/cip309) —
an open standard for **Proof of Existence (PoE)** anchored on the Cardano
blockchain. Hash content, publish the digest on-chain under metadata label 309,
and let anyone prove "this content existed on or before block time T" without
trusting any server, domain, or issuer identity.

This repository is a small pnpm workspace of three packages that build on one
another:

| Package | What it is |
| --- | --- |
| [`@cardanowall/crypto-core`](packages/crypto-core) | Closed-catalogue cryptographic primitives: hash, KDF, signature, KEM, AEAD, CBOR, COSE, sealed-PoE, Merkle, diceware. |
| [`@cardanowall/poe-standard`](packages/poe-standard) | The CIP-309 record schema, canonical-CBOR encoder, structural validator, and error-code catalogue — the wire-format library. |
| [`@cardanowall/sdk-ts`](packages/sdk-ts) | The high-level SDK: a standalone verifier (three roles), a gateway-agnostic HTTP client, off-host signing, and seed-derived identity helpers. Runs in the browser, Node.js, Deno, and Bun. |

`sdk-ts` depends on `poe-standard`, which depends on `crypto-core`; the three
ship together so the closure resolves as one published unit.

## Install

```sh
npm install @cardanowall/sdk-ts
```

`@cardanowall/poe-standard` and `@cardanowall/crypto-core` are pulled in
automatically as dependencies; install them directly only if you want the
lower-level surface on its own.

## Quickstart

Verify any CIP-309 transaction from chain metadata alone — no issuer server in
the trust path:

```ts
import { verifyTx } from '@cardanowall/sdk-ts/verifier';

const report = await verifyTx({
  txHash: '<64-hex Cardano transaction hash>',
  // Supply a gateway/provider for chain metadata; the verifier itself trusts
  // no vendor — it routes through a public explorer you choose.
});

console.log(report.verdict); // 'valid' | 'invalid' | ...
```

See [`packages/sdk-ts/README.md`](packages/sdk-ts/README.md) for the full
surface: publishing against any gateway, off-host signing, recipient
decryption, and seed-derived identities.

## Develop

```sh
pnpm install
pnpm -r build        # build all three packages (tsup)
pnpm exec vitest run # full test suite (unit + KAT + integration + nxdomain)
pnpm -r typecheck
```

The test suite includes the cross-implementation **conformance vectors** and a
synthetic **mainnet corpus**; these same vectors are replayed by the Python and
Rust SDKs, which is what keeps all three byte-identical.

## The standard and sibling implementations

- [`cip309`](https://github.com/cardanowall/cip309) — the standard: prose spec,
  CDDL grammar, JSON schemas, registries, and the canonical conformance vectors.
- [`cip309-py`](https://github.com/cardanowall/cip309-py) — the Python SDK
  (byte-parity twin).
- [`cip309-rs`](https://github.com/cardanowall/cip309-rs) — the Rust SDK
  (byte-parity twin).
- [`cip309-cli`](https://github.com/cardanowall/cip309-cli) — the
  `cardanowall` command-line tool.

## License

[Apache-2.0](LICENSE).
