# @cardanowall/sdk-ts — the TypeScript SDK for Label 309 Proof-of-Existence

The browser + Node TypeScript SDK for [Label 309](https://github.com/cardanowall/label-309) Proof-of-Existence on Cardano: a **standalone verifier** (three roles), a **gateway-agnostic HTTP client**, **off-host signing** helpers, and **seed-derived identity** helpers.

## What it is

Label 309 anchors a content hash on Cardano under metadata label 309 so that anyone can later prove "this content existed on or before block time T" — without trusting any server, domain, or issuer identity. This package is the high-level TypeScript surface over that standard:

- **Verify** any Label 309 transaction from chain metadata alone — no issuer server in the trust path.
- **Publish, read, and decrypt** records against **any** Label 309 gateway (you supply the base URL and an opaque key).
- **Sign** records off-host (AWS KMS, GCP HSM, YubiHSM, air-gapped) — the private key never touches the SDK.
- **Derive identity** keypairs, recipient strings, signers, and sealed-PoE decryption from a single 32-byte seed.

It builds on two lower-level packages — [`@cardanowall/poe-standard`](../poe-standard) (the wire format) and [`@cardanowall/crypto-core`](../crypto-core) (the primitives) — and re-exports the parts a consumer needs. The verifier and sealed-PoE logic are **byte-identical** to the [Python](../sdk-py) and [Rust](../sdk-rs) twins, validated against shared canonical-CBOR test vectors. Runs in the browser, Node.js, Deno, and Bun.

## Install

```sh
npm install @cardanowall/sdk-ts
```

## Quick start

### Verify a record (standalone — no gateway, no issuer trust)

`verifyTx` fetches the transaction from a Cardano gateway you specify, extracts the label-309 metadata, runs the structural validator, checks confirmation depth, and verifies any record-level signatures. It reaches only the gateways you pass — no fixed deployment is contacted.

```ts
import { verifyTx } from '@cardanowall/sdk-ts';

const report = await verifyTx({
  txHash: '<64-char hex tx hash>',
  cardanoGatewayChain: ['https://api.koios.rest/api/v1'], // tried in order
});

console.log(report.verdict); // 'valid' | 'pending' | 'unverifiable' | 'failed'
console.log(report.exit_code); // 0 valid · 1 integrity fail · 2 network fail · 3 pending
console.log(report.record); // the decoded Label 309 PoeRecord
```

To decrypt a sealed PoE addressed to you, run at the **recipient-sealed** profile and supply your X25519 private key. The keyring is global to the run — each credential is tried against every sealed item, so there is no per-item index:

```ts
const report = await verifyTx({
  txHash: '<tx hash>',
  cardanoGatewayChain: ['https://api.koios.rest/api/v1'],
  arweaveGatewayChain: ['https://arweave.net'],
  profile: 'recipient-sealed',
  decryption: [{ recipientSecretKey: myX25519SecretKey }],
});
// report.item_decryptions[0].verdict === 'decrypted'
// report.item_decryptions[0].plaintext_hash_ok === true
```

When you already hold the metadata bytes from an indexer mirror, skip the chain round-trip with `verifyResolved({ txHash, metadataCbor, numConfirmations, ... })`.

### Talk to a gateway (publish, read, balance)

`baseUrl` is **required** and must include the API version segment (e.g. `https://gateway.example.com/api/v1`) — the client binds to no particular deployment and appends only the bare resource suffix, so the version (and any proxy path prefix) lives entirely in this value. `apiKey`, when present, is an **opaque** bearer token forwarded verbatim as `Authorization: Bearer <apiKey>`; the SDK never parses or assumes its format. Omit it for anonymous read-only use.

```ts
import { Label309Client } from '@cardanowall/sdk-ts';

const client = new Label309Client({
  baseUrl: 'https://gateway.example.com/api/v1', // any Label 309 gateway; include the version segment
  apiKey: process.env.LABEL309_API_KEY, // opaque; omit for anonymous reads
});

// Read surface — no auth required for public records.
const record = await client.records.get('<tx hash>');
// To verify a record, run the standalone verifier (see above) — the gateway
// hosts no verify endpoint, so a verdict never depends on trusting a server.

// Authenticated read.
const { balanceUsdMicros } = await client.account.balance(); // decimal string, never coerced
```

PoE submissions debit the gateway's own balance model, so every publish needs a price lock. Request a quote first, then pass `quote_id` to the publish call:

```ts
const quote = await client.poe.quote({
  recordBytes: 256,
  recipientCount: 0,
  fileBytesTotal: 0,
});

// Hash-only PoE: hash the content, build the record, submit. One HTTP call.
const result = await client.poe.publishContent({
  content: 'hello world', // string (UTF-8) or Uint8Array
  quoteId: quote.quote_id,
  // signer is optional; omit to publish unsigned (profile=core)
});
console.log(result.id, result.status, result.balance_after_usd_micros);
```

`publishContent` / `publishPrehashed` also co-hash the content under several algorithms (`hashAlgs: ['sha2-256', 'blake2b-256']`, bound into one item) and accept optional `uris` (already-pinned `ar://` / `ipfs://` content mirrors) and a `supersedes` link to an earlier record. `client.poe` further exposes the low-level `uploads` / `publish` / `publishBatch`, and `quote`. `client.records.list({ sealed: true })` pages through the sealed records addressed to the authenticated account (the gateway resolves "addressed to me" from the bearer identity).

The priced helpers quote internally, so they take a `maxUsdMicros` price cap instead of a `quoteId`. `publishMerkle({ leaves, leafAlg?, maxUsdMicros?, signer? })` commits N leaf hashes under one RFC 9162 root and returns the exact published `recordBytes`. The sealed flow is two-phase, so a failed publish never re-encrypts or re-pays storage:

```ts
import { sealPrepare, preparedSealToJson, preparedSealFromJson } from '@cardanowall/sdk-ts';

// Phase 1 — pure and offline: encrypt every item to the recipient set.
const prepared = sealPrepare({
  items: [{ content: fileBytes }],
  recipients: [recipientPublicKey], // 1216-byte X-Wing keys (or 32-byte x25519 with kem: 'x25519')
});
persist(preparedSealToJson(prepared)); // the portable prepared_seal_json_v1 artifact

// Optional price preview before committing to storage.
const quote = await client.poe.quotePreparedSeal({ prepared });

// Phase 2 — online: quote → upload ciphertexts → publish. A failure after a
// paid upload throws a `SubmitSealedError` whose `uploads` are validated
// receipts; persist them and pass them back as `uploaded` on the retry to
// resume without re-uploading (or re-paying for) that storage.
import { SubmitSealedError, type UploadReceipt } from '@cardanowall/sdk-ts';

async function submit(uploaded: readonly UploadReceipt[] = []) {
  try {
    return await client.poe.submitSealed({
      prepared: preparedSealFromJson(restore()),
      maxUsdMicros: 2_000_000n, // refuse to spend more than $2
      uploaded, // receipts recovered from a prior attempt, if any
    });
  } catch (err) {
    if (err instanceof SubmitSealedError) persist(err.uploads); // resume from these later
    throw err;
  }
}

const submission = await submit();
console.log(submission.response.id, submission.uris, submission.recordBytes);
```

`client.poe.publishSealed({ items, recipients, ... })` is the one-shot form of the same flow (prepare + submit in one call) for flows that need no crash resume.

To deliver to someone who has no Label 309 identity, seal to a **shared passphrase** instead of recipient keys — anyone who knows it opens the record, with no delivery address involved. The passphrase surface mirrors the recipient one: two-phase `passphraseSealPrepare` + `submitPassphraseSealed` (with `quotePreparedPassphraseSeal` for a preview and `UploadReceipt` resume), plus a one-shot wrapper. Read the passphrase from the environment or a prompt, never a source-embedded literal:

```ts
const passphrase = process.env.SEAL_PASSPHRASE!;

const submission = await client.poe.publishPassphraseSealed({
  items: [{ content: fileBytes }],
  passphrase,
  hashAlgs: ['sha2-256', 'blake2b-256'], // co-hash the item under both algorithms
  maxUsdMicros: 500_000n, // refuse to spend more than $0.50
});
console.log(submission.response.id, submission.uris);
```

A recipient opens it by passing the passphrase to `verifyTx` — a `{ passphrase }` entry in `decryption` joins the same keyring as any recipient key and is tried against every sealed item.

### Sign off-host (key never enters the SDK)

The signing surface touches only public data — the canonical record bytes (in) and the 32-byte public key + 64-byte signature (out). Your signer callback owns the private key, whether that is AWS KMS, a YubiHSM, or an air-gapped workstation.

```ts
import { prepareSigStructure, assembleCoseSign1 } from '@cardanowall/sdk-ts';

// 1. Build the COSE Sig_structure bytes to be signed.
const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });

// 2. Sign those bytes anywhere — KMS, HSM, offline. Return 64 raw Ed25519 bytes.
const signature = await myExternalSigner(sigStructureBytes);

// 3. Assemble the COSE_Sign1 and the chunked sigs[] entry for the record.
const { sigEntry } = assembleCoseSign1({ record, signerPubkey, signature });
```

### Identity from a 32-byte seed

A developer holding a raw seed derives every keypair, recipient string, signer, and sealed-PoE decryption — no web account envelope required.

```ts
import {
  deriveKeysFromSeed,
  recipientsFromSeed,
  signerFromSeed,
  decryptSealedFromSeed,
} from '@cardanowall/sdk-ts';

const keys = deriveKeysFromSeed(seed); // { ed25519, x25519, mlkem768x25519 }
const me = recipientsFromSeed(seed); // { age: 'age1…', age1pqc: 'age1pqc…' }
const signer = signerFromSeed(seed); // a path-1 Signer for the publish helpers

// Decrypt a sealed PoE addressed to this seed — works for both classical
// (x25519) and hybrid post-quantum (mlkem768x25519 / X-Wing) records.
const result = decryptSealedFromSeed({ seed, envelope, ciphertext });
if (result.matched) {
  console.log(result.plaintext);
}
```

## API overview

Everything is reachable from the package root; submodule entry points (`/verifier`, `/client`, `/identity`, `/merkle`, `/hash`, `/fetch`) exist for tree-shaking.

**Verifier** (`@cardanowall/sdk-ts` or `/verifier`)

- `verifyTx(input)` / `verifyResolved(input)` — the full pipeline; returns a `VerifyReport`.
- `verifyRecordSignatures`, `verifyMerkleCommitments`, `tryDecryptions` — individual stages.
- `DEFAULT_PROFILE`, `profileImplements`, `planProfileSkips` — the four conformance profiles (`core` → `signed` → `sealed` → `recipient-sealed`).
- `CONFIRMATION_DEPTH_THRESHOLD_DEFAULT` (15), `exitCodeForVerdict`, `verifyReportToDict`.
- `resolveCardanoTx`, `extractLabel309Metadata`, `decodeTxWitnesses`, `decodeTxSummary` — resolution + transaction-level description.

**Client** (`/client`)

- `Label309Client({ baseUrl, apiKey?, fetch? })` — `baseUrl` required, key opaque.
- `client.poe.{quote, publishContent, publishPrehashed, quotePreparedSeal, submitSealed, publishSealed, quotePreparedPassphraseSeal, submitPassphraseSealed, publishPassphraseSealed, publishMerkle, uploads, publish, publishBatch}`. `publishContent` co-hashes via `hashAlgs` and accepts `uris` + `supersedes`.
- Two-phase sealed publishing: `sealPrepare` (to recipients) / `passphraseSealPrepare` (to a shared passphrase), `preparedSealToJson` / `preparedSealFromJson` (the portable `prepared_seal_json_v1` artifact), `sealedRecord` / `encodeSealedRecord` (air-gap assembly seams), plus `UploadReceipt`-carrying errors (`SubmitSealedError`).
- `client.records.{list, count, get}`, `client.account.balance()`. Sealed records addressed to the caller come from `client.records.list({ sealed: true })` — there is no server-side verify endpoint, so a verdict always runs through the standalone verifier.
- Off-host signing: `prepareSigStructure`, `assembleCoseSign1`, plus the CIP-8 hashed-mode pair `prepareSigStructureHashed` / `assembleCoseSign1Hashed`.
- HTTP errors extending `Label309HttpError`: `InsufficientFundsError`, `QuoteExpiredError`, `QuoteAlreadyConsumedError`, `ServiceUnavailableError` (503, e.g. no FX snapshot yet — retryable), `RateLimitedError`, `UnauthorizedError`, `ValidationFailedError`, `MalformedCborError`, and more. Client-side errors extend plain `Error`: `InvalidClientConfigError` (bad config) and `MaxUsdExceededError` (a quote exceeded the `maxUsdMicros` cap).

**Identity** (`/identity`)

- `deriveKeysFromSeed`, `recipientsFromSeed`, `signerFromSeed`, `recipientKeyBundleFromSeed`, `decryptSealedFromSeed`.
- Recipient codecs `encodeAgeX25519Recipient`, `encodeAgeXWingRecipient`, `parseAgeRecipient`.
- Low-level derive primitives `deriveEd25519KeypairFromSeed`, `deriveX25519KeypairFromSeed`, `deriveMlKem768X25519KeypairFromSeed`.

**Wire format & primitives** (re-exported for convenience)

- From `@cardanowall/poe-standard`: `validatePoeRecord`, `encodePoeRecord`, `encodeRecordBodyForSigning`, the error-code catalogues (`STRUCTURAL_ERROR_CODES`, `VERIFIER_ERROR_CODES`, `ERROR_CODES`), `severityOf`, `PoeRecordSchema`.
- From `@cardanowall/crypto-core`: `eciesSealedPoeWrap` / `eciesSealedPoeUnwrap` (sealed PoE), `hash.*` (digests), `merkle.*` (`merkleSha2256Root`, `merkleSha2256InclusionProof`, `merkleSha2256VerifyInclusion`, leaves-list codecs).

**Egress** (`/fetch`) — the verifier's single network egress point: `fetchOutbound`, `wrapFetchOutbound`, the deny-host guard (`DENY_HOSTS_DEFAULT`, `DenyHostError`), and `BodyTooLargeError`. Inject your own `fetchOutbound` to fully control where the verifier may reach. The `webhook` purpose (a fetch whose target URL came from end-user input) is rejected by design: safe webhook egress needs a DNS-pinning SSRF guard, which this package does not provide.

See the package source for the exhaustive list.

## The three verifier roles

A consumer picks how far down the trust chain to go:

- **Structural validator** — a pure function over the CBOR bytes (`validatePoeRecord`). No I/O, no signatures, no decryption.
- **Public verifier** — `verifyTx` at profile `core` or `signed`: fetches metadata, runs structural validation, verifies record signatures. Does not decrypt.
- **Recipient verifier** — `verifyTx` at profile `recipient-sealed` with a `decryption` entry: the public verifier plus an X25519 private key that decrypts a sealed PoE and recomputes the plaintext hashes.

## Sealed PoE & post-quantum

Sealed records wrap a content-encryption key to one or more recipient public keys (age-style sealed envelope). The default KEM is **X-Wing** (`mlkem768x25519`, hybrid ML-KEM-768 + X25519), addressed by `age1pqc…` recipient strings; the classical `x25519` path (`age1…`) remains available. Both decrypt through the same `decryptSealedFromSeed` / `tryDecryptions` dispatch, which selects the right secret from the envelope's `kem` field.

## Cross-implementation parity

The verifier, the structural validator, the sealed-PoE construction, the off-host signing builder, and the seed-derivation are **byte-identical** across the TypeScript, [Python](../sdk-py), and [Rust](../sdk-rs) SDKs. Parity is enforced by shared known-answer-test corpora (canonical-CBOR record bodies, COSE_Sign1 build vectors, seed-derive vectors, recipient-string vectors). A record published or signed by one implementation verifies identically under the others.

## Standard & service independence

A Label 309 proof verifies from three inputs only: the **transaction metadata**, optionally the **content bytes**, and a **public blockchain explorer**. No issuer server sits in the trust path. `verifyTx` reaches only the gateway chains you pass it, routes every outbound request through a single auditable egress point (every call lands in `VerifyReport.http_calls`), and enforces a deny-host policy — so the standalone verifier can be pointed at any infrastructure and still produce a trustworthy verdict.

## Relation to the other packages

- **`@cardanowall/crypto-core`** — closed-catalogue cryptographic primitives (hash, KDF, signature, KEM, AEAD, CBOR, COSE, sealed-PoE, Merkle, recipient encoding, seed derivation). The building blocks this SDK is built on.
- **`@cardanowall/poe-standard`** — the Label 309 wire-format library: record schema, canonical-CBOR encoder, pure structural validator, error-code catalogue.
- **`@cardanowall/sdk-py`** — the Python SDK: a byte-identical parity twin of this package, validated against the same canonical-CBOR vectors.
- **`cardanowall`** (Rust crate) — the Rust SDK: the byte-parity twin in Rust, blocking HTTP, secure-by-default egress. The `cardanowall` CLI is built on it.

## License

Apache-2.0.
