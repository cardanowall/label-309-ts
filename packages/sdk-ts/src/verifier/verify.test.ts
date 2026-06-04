// Verifier pipeline integration tests — happy path + the load-bearing
// verdict-mapping invariants (3-state verdict, INSUFFICIENT_CONFIRMATIONS →
// 'pending'/exit 3, network-class → 'failed'/exit 2, etc.). Uses hand-built
// minimal fixtures that exercise every shape in the spec; the byte-pinned
// cross-implementation corpus lives in the parity test suites.

import { describe, expect, it } from 'vitest';

import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import { coseSign1Label309Build } from '@cardanowall/crypto-core/cose';
import { merkleSha2256Root, sha256 } from '@cardanowall/crypto-core/hash';
import { x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { eciesSealedPoeWrap } from '@cardanowall/crypto-core/sealed-poe';
import { getPublicKeyEd25519 } from '@cardanowall/crypto-core/sig';
import { encodeRecordBodyForSigning, PoeRecordSchema } from '@cardanowall/poe-standard';

import type { FetchOutbound, FetchOutboundOptions, FetchOutboundResult } from './types';
import { verifyTx } from './verify';

const TX_HASH = '0'.repeat(64);
const KOIOS_MAINNET = 'https://api.koios.rest/api/v1';
const ARWEAVE_TXID_1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function makeSeed(byte: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function chunkBytes(value: Uint8Array, size = 64): Uint8Array[] {
  if (value.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array[] = [];
  for (let i = 0; i < value.length; i += size) {
    out.push(value.subarray(i, Math.min(i + size, value.length)));
  }
  return out;
}

function jsonResponse(value: unknown, status = 200): FetchOutboundResult {
  return { status, bytes: new TextEncoder().encode(JSON.stringify(value)), durationMs: 1 };
}

function bytesResponse(bytes: Uint8Array, status = 200): FetchOutboundResult {
  return { status, bytes, durationMs: 1 };
}

function emptyResponse(status: number): FetchOutboundResult {
  return { status, bytes: new Uint8Array(0), durationMs: 1 };
}

type Route = (url: string, opts: FetchOutboundOptions) => FetchOutboundResult | undefined;
function mkStubFetch(routes: Route[]): FetchOutbound {
  return async (url, opts) => {
    for (const r of routes) {
      const res = r(url, opts);
      if (res !== undefined) return res;
    }
    return emptyResponse(500);
  };
}

interface BuildFixtureOpts {
  readonly withRecordSig?: boolean;
  readonly tamperRecordSig?: boolean;
  readonly recordSigSeed?: Uint8Array;
  readonly noLabel309?: boolean;
  readonly sealedItem?: {
    readonly plaintext: Uint8Array;
    readonly recipientPub: Uint8Array;
    readonly arweaveTxid: string;
  };
  // Merkle commit attached at record level — the verifier walks this in step
  // 6 (verify.ts), calling `verifyMerkleCommitments` which by default issues
  // an outbound fetch to the on-record `uris[]`. Tests using this flag
  // exercise the `verifyMerkle` opt-out used by SSR consumers.
  readonly withMerkleCommit?: { readonly arweaveTxid: string };
}

interface Fixture {
  readonly txCbor: Uint8Array;
  readonly recordSignerPub?: string;
  readonly ciphertext?: Uint8Array;
}

function buildFixture(opts: BuildFixtureOpts): Fixture {
  if (opts.noLabel309) {
    const txValue: CanonicalCborValue = [
      new Map<string, string>([['x', 'body']]),
      new Map<string, string>([['x', 'witness_set']]),
      true,
      null,
    ];
    return { txCbor: encodeCanonicalCbor(txValue) };
  }

  const items: CanonicalCborValue[] = [];
  let ciphertext: Uint8Array | undefined;
  if (opts.sealedItem !== undefined) {
    const wrap = eciesSealedPoeWrap({
      plaintext: opts.sealedItem.plaintext,
      recipientPublicKeys: [opts.sealedItem.recipientPub],
    });
    ciphertext = wrap.ciphertext;
    const env = wrap.envelope;
    // The wrap above uses the default classical x25519 KEM, so the slots carry
    // { epk, wrap }; narrow on the discriminant to read them.
    const encSlots =
      env.kem === 'mlkem768x25519'
        ? env.slots.map((s) => ({ kem_ct: s.kem_ct.map((c) => c), wrap: s.wrap }))
        : env.slots.map((s) => ({ epk: s.epk, wrap: s.wrap }));
    const item: Record<string, CanonicalCborValue> = {
      hashes: { 'sha2-256': sha256(opts.sealedItem.plaintext) },
      uris: [[`ar://${opts.sealedItem.arweaveTxid}`]],
      enc: {
        scheme: env.scheme,
        aead: env.aead,
        kem: env.kem,
        nonce: env.nonce,
        slots: encSlots,
        slots_mac: env.slots_mac,
      },
    };
    items.push(item);
  } else {
    items.push({ hashes: { 'sha2-256': new Uint8Array(32).fill(7) } });
  }

  const recordValue: Record<string, CanonicalCborValue> = { v: 1, items };

  if (opts.withMerkleCommit !== undefined) {
    // Two-leaf Merkle tree → real root, real leaf_count. The on-record
    // URI points at the supplied Arweave txid (43-char base64url id).
    const leafA = new Uint8Array(32).fill(0x01);
    const leafB = new Uint8Array(32).fill(0x02);
    const root = merkleSha2256Root([leafA, leafB]);
    recordValue['merkle'] = [
      {
        alg: 'rfc9162-sha256',
        root,
        leaf_count: 2,
        uris: [[`ar://${opts.withMerkleCommit.arweaveTxid}`]],
      },
    ];
  }

  let recordSignerPub: string | undefined;
  if (opts.withRecordSig) {
    const seed = opts.recordSigSeed ?? makeSeed(11);
    const pub = getPublicKeyEd25519({ seed });
    recordSignerPub = bytesToHex(pub);
    // Build the record body MINUS sigs and sign over canonical-CBOR(body)
    // with the v1 domain prefix — `coseSign1Label309Build` handles the prefix
    // and Sig_structure construction.
    const tempRecord = PoeRecordSchema.parse({ ...recordValue });
    const recordBodyCbor = encodeRecordBodyForSigning(tempRecord);
    const protectedHeader = new Map<number, unknown>([
      [1, -8],
      [4, pub],
    ]);
    let cose = coseSign1Label309Build({
      protectedHeader,
      unprotectedHeader: new Map(),
      recordBodyCbor,
      signerSecretKey: seed,
    });
    if (opts.tamperRecordSig) {
      cose = new Uint8Array(cose);
      cose[cose.length - 30] = (cose[cose.length - 30]! + 1) & 0xff;
    }
    recordValue['sigs'] = [{ cose_sign1: chunkBytes(cose) }];
  }

  const recordBytes = encodeCanonicalCbor(recordValue as CanonicalCborValue);
  const recordValueRoundTripped = decodeCanonicalCbor(recordBytes);
  // Build a tx CBOR shape: [body, witness_set, is_valid, aux_map]; aux_map is
  // a bare CBOR map `{0 => metadata}` (pre-Alonzo fallback shape — the
  // cbor-walker accepts either tag-259 or bare map).
  const metadataMap = new Map<number, unknown>();
  metadataMap.set(309, recordValueRoundTripped);
  const auxMap = new Map<number, unknown>();
  auxMap.set(0, metadataMap);
  const txCbor = encodeCanonicalCbor([
    new Map<string, string>([['x', 'body']]),
    new Map<string, string>([['x', 'witness_set']]),
    true,
    auxMap as unknown as CanonicalCborValue,
  ] as readonly CanonicalCborValue[]);

  return {
    txCbor,
    ...(recordSignerPub !== undefined && { recordSignerPub }),
    ...(ciphertext !== undefined && { ciphertext }),
  };
}

function koiosStub(
  txCbor: Uint8Array,
  numConfirmations: number,
  options?: { koiosUrl?: string },
): Route {
  const url = options?.koiosUrl ?? KOIOS_MAINNET;
  return (u) => {
    if (u === `${url}/tx_cbor`) {
      return jsonResponse([{ tx_hash: TX_HASH, cbor: bytesToHex(txCbor) }]);
    }
    if (u === `${url}/tx_info`) {
      return jsonResponse([
        {
          tx_hash: TX_HASH,
          num_confirmations: numConfirmations,
          tx_timestamp: 1700000000,
          absolute_slot: 99,
        },
      ]);
    }
    return undefined;
  };
}

describe('verifyTx — happy path', () => {
  it('record-sig (path 1, in-signature kid) → verdict valid, exit 0', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.exit_code).toBe(0);
    expect(r.profile).toBe('recipient-sealed');
    expect(r.record_signatures).toEqual([
      {
        index: 0,
        verdict: 'valid',
        signer_type: 'in-signature-kid',
        signer_pub: fix.recordSignerPub,
      },
    ]);
    expect(r.metadata_present).toBe(true);
  });

  it('record-sig + sealed-PoE decryption end-to-end → verdict valid', async () => {
    const recipientSecret = makeSeed(50);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('hello-world');
    const fix = buildFixture({
      withRecordSig: true,
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (u) =>
        u === `https://arweave.net/${ARWEAVE_TXID_1}` ? bytesResponse(fix.ciphertext!) : undefined,
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.record_signatures?.[0]?.verdict).toBe('valid');
    expect(r.item_decryptions).toEqual([
      { item_index: 0, verdict: 'decrypted', plaintext_hash_ok: true },
    ]);
  });
});

describe('verifyTx — three-state verdict mapping', () => {
  it('INSUFFICIENT_CONFIRMATIONS → verdict pending, exit 3 (NOT failed)', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 5)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('pending');
    expect(r.exit_code).toBe(3);
    expect(r.validation.issues?.[0]?.code).toBe('INSUFFICIENT_CONFIRMATIONS');
    // Below the confirmation threshold the verifier short-circuits before any
    // signature work, so no record_signatures are produced.
    expect(r.record_signatures).toBeUndefined();
  });

  it('explicit threshold 1 lets 5 confirmations pass → verdict valid', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 5)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      confirmationDepthThreshold: 1,
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
  });

  it('PROVIDER_UNAVAILABLE (all gateways 503) → verdict failed, exit 2 (network class)', async () => {
    const stub: FetchOutbound = async () => emptyResponse(503);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(2);
    expect(r.validation.issues?.[0]?.code).toBe('PROVIDER_UNAVAILABLE');
  });

  it('METADATA_NOT_FOUND (no label-309) → verdict failed, exit 1', async () => {
    const fix = buildFixture({ noLabel309: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(1);
    expect(r.metadata_present).toBe(false);
  });

  it('SIGNATURE_INVALID → verdict failed, exit 1', async () => {
    const fix = buildFixture({ withRecordSig: true, tamperRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(1);
    expect(r.record_signatures?.[0]?.verdict).toBe('invalid');
    expect(r.record_signatures?.[0]?.reason).toBe('SIGNATURE_INVALID');
  });
});

describe('verifyTx — conformance profiles', () => {
  it("profile='core' reading a record with sigs emits OUT_OF_PROFILE_SKIPPED (info) and skips sig verification", async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      profile: 'core',
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.profile).toBe('core');
    expect(r.record_signatures).toBeUndefined();
    const info = r.validation.info ?? [];
    expect(info.some((i) => i.code === 'OUT_OF_PROFILE_SKIPPED')).toBe(true);
  });

  it("profile='signed' verifies sigs but skips decrypt requests", async () => {
    const recipientSecret = makeSeed(60);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('signed-no-decrypt');
    const fix = buildFixture({
      withRecordSig: true,
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      profile: 'signed',
      cardanoGatewayChain: [KOIOS_MAINNET],
      // decryption supplied but profile gates it off
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.record_signatures?.[0]?.verdict).toBe('valid');
    expect(r.item_decryptions).toBeUndefined();
  });
});

describe('verifyTx — service independence (denyHosts)', () => {
  it('denyHosts on the Cardano gateway → verdict failed (provider unavailable)', async () => {
    const stub: FetchOutbound = async () => bytesResponse(new Uint8Array(0));
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      denyHosts: ['api.koios.rest'],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(2);
    expect(r.http_calls.some((c) => c.url.includes('api.koios.rest') && c.status === 0)).toBe(true);
  });
});

describe('verifyTx — sealed-PoE decryption failure modes', () => {
  it('wrong recipient key → verdict failed, decryption verdict wrong-key', async () => {
    const recipientSecret = makeSeed(70);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('top-secret');
    const fix = buildFixture({
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    const wrongSecret = makeSeed(99);
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (u) =>
        u === `https://arweave.net/${ARWEAVE_TXID_1}` ? bytesResponse(fix.ciphertext!) : undefined,
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: wrongSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(1);
    expect(r.item_decryptions?.[0]?.verdict).toBe('wrong-key');
  });

  it('CONTENT_UNAVAILABLE → verdict failed, exit 2 (network class)', async () => {
    const recipientSecret = makeSeed(80);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('content-unavailable');
    const fix = buildFixture({
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      // every Arweave gateway returns 500
      (u) => (u.includes('/AAAA') ? emptyResponse(500) : undefined),
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exit_code).toBe(2);
    expect(r.item_decryptions?.[0]?.verdict).toBe('content-unavailable');
  });

  it('out-of-band ciphertextBytes takes precedence over uris[] (no fetch issued)', async () => {
    const recipientSecret = makeSeed(81);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('oob-bytes');
    const fix = buildFixture({
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    let arweaveCalls = 0;
    const stub: FetchOutbound = async (url, opts) => {
      if (url.endsWith('/tx_cbor')) {
        return jsonResponse([{ tx_hash: TX_HASH, cbor: bytesToHex(fix.txCbor) }]);
      }
      if (url.endsWith('/tx_info')) {
        return jsonResponse([
          { tx_hash: TX_HASH, num_confirmations: 50, tx_timestamp: 1, absolute_slot: 1 },
        ]);
      }
      if (opts.purpose === 'arweave') {
        arweaveCalls++;
        return bytesResponse(fix.ciphertext!);
      }
      return emptyResponse(500);
    };
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      ciphertextBytes: { 0: fix.ciphertext! },
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(arweaveCalls).toBe(0);
  });
});

describe('verifyTx — offline switch (verifyMerkle:false) suppresses all URI egress', () => {
  // `verifyMerkle:false` is the master offline switch: past the chain/indexer
  // resolve step the verifier must issue ZERO outbound fetches — neither the
  // Merkle leaves-list nor a sealed item's ciphertext. This is what the CLI's
  // `--no-fetch` and the SSR viewer rely on.
  it('does NOT fetch a sealed item ciphertext; surfaces ciphertext-unavailable with no egress', async () => {
    const recipientSecret = makeSeed(82);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('offline-no-fetch');
    const fix = buildFixture({
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    let arweaveCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (_u, opts) => {
        if (opts.purpose === 'arweave' || opts.purpose === 'ipfs') {
          arweaveCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
      verifyMerkle: false,
    });
    // No ciphertext could be acquired without fetching, so decryption reports
    // ciphertext-unavailable — and crucially, zero outbound storage fetches.
    expect(arweaveCalls).toBe(0);
    expect(r.item_decryptions?.[0]?.verdict).toBe('ciphertext-unavailable');
    // Only the chain resolve calls (tx_cbor + tx_info) appear in the audit;
    // nothing with an arweave/ipfs purpose.
    expect(r.http_calls.every((c) => c.purpose === 'cardano')).toBe(true);
  });

  it('still decrypts offline from out-of-band ciphertextBytes with verifyMerkle:false', async () => {
    const recipientSecret = makeSeed(83);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('offline-oob');
    const fix = buildFixture({
      sealedItem: { plaintext, recipientPub, arweaveTxid: ARWEAVE_TXID_1 },
    });
    let arweaveCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (_u, opts) => {
        if (opts.purpose === 'arweave' || opts.purpose === 'ipfs') {
          arweaveCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ itemIndex: 0, recipientSecretKey: recipientSecret }],
      ciphertextBytes: { 0: fix.ciphertext! },
      fetchOutbound: stub,
      verifyMerkle: false,
    });
    expect(arweaveCalls).toBe(0);
    expect(r.item_decryptions?.[0]?.verdict).toBe('decrypted');
    expect(r.item_decryptions?.[0]?.plaintext_hash_ok).toBe(true);
  });
});

describe('verifyTx — record shape exposes new fields', () => {
  it('exposes profile + numConfirmations + httpCalls', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.profile).toBe('recipient-sealed');
    expect(r.num_confirmations).toBe(50);
    expect(r.confirmation_depth_threshold).toBe(15);
    expect(r.http_calls.length).toBeGreaterThan(0);
  });
});

describe('verifyTx — verifyMerkle opt-out', () => {
  // The verifier's default Merkle pipeline issues an outbound fetch for the
  // on-record leaves-list, which is the right semantics for the CLI / full
  // verification flow but the wrong fit for server-rendered viewers that
  // already serve their record from an indexed CBOR mirror. The
  // `verifyMerkle: false` flag lets the SSR caller render `record.merkle[]`
  // metadata (alg, root, leaf_count, uris) WITHOUT triggering the
  // Arweave/IPFS gateway rotation — moving the leaves-list re-root from
  // SSR cost to a user-initiated client-side action.
  it('skips the leaves-list fetch entirely (no merkle_checks, no Arweave call)', async () => {
    const fix = buildFixture({ withMerkleCommit: { arweaveTxid: ARWEAVE_TXID_1 } });
    let arweaveCallCount = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (u) => {
        if (u.startsWith('https://arweave.net/') || u.startsWith('https://ar-io.net/')) {
          arweaveCallCount += 1;
          return bytesResponse(new Uint8Array(0), 404);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
      verifyMerkle: false,
    });
    expect(r.verdict).toBe('valid');
    expect(r.merkle_checks).toBeUndefined();
    expect(arweaveCallCount).toBe(0);
    // The on-record merkle metadata is still surfaced on `record.merkle[]`
    // for the viewer to render the commit card.
    expect(r.record?.merkle?.[0]?.leaf_count).toBe(2);
  });

  it('default (omitted) still runs the leaves-list fetch (CLI-compatible)', async () => {
    const fix = buildFixture({ withMerkleCommit: { arweaveTxid: ARWEAVE_TXID_1 } });
    let arweaveCallCount = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txCbor, 50),
      (u) => {
        if (u.startsWith('https://arweave.net/') || u.startsWith('https://ar-io.net/')) {
          arweaveCallCount += 1;
          return bytesResponse(new Uint8Array(0), 404);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
      // No verifyMerkle flag → defaults to `true`, fetch runs.
    });
    expect(r.merkle_checks?.[0]?.verdict).toBe('unavailable');
    expect(arweaveCallCount).toBeGreaterThanOrEqual(1);
  });
});
