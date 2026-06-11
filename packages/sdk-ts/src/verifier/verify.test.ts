// Verifier pipeline integration tests — happy path plus the load-bearing
// verdict-mapping invariants: the four-state verdict/exit-code mapping,
// the integrity/attribution/availability split on fetched content, the
// confirmation-depth pending halt, profile gating, and the offline
// `fetchContent` switch. Uses hand-built minimal fixtures whose transaction
// bytes genuinely satisfy the transaction-reference integrity binding; the
// byte-pinned cross-implementation corpus lives in the KAT suites.

import { describe, expect, it, vi } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { coseSign1Label309Build } from '@cardanowall/crypto-core/cose';
import { blake2b256, merkleSha2256Root, sha256 } from '@cardanowall/crypto-core/hash';
import { x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { encodeLeavesList } from '@cardanowall/crypto-core/merkle';
import { eciesSealedPoeWrap } from '@cardanowall/crypto-core/sealed-poe';
import { getPublicKeyEd25519 } from '@cardanowall/crypto-core/sig';
import {
  chunkRecordBody,
  encodePoeRecord,
  PoeRecordSchema,
  encodeRecordBodyForSigning,
  type PoeRecord,
} from '@cardanowall/poe-standard';

import type { FetchOutbound, FetchOutboundOptions, FetchOutboundResult } from './types';
import { verifyResolved, verifyTx } from './verify';

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

// Base32 (RFC 4648 lowercase, no padding) for building raw-codec CIDv1
// strings whose multihash binding the verifier can actually verify.
function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(acc >> bits) & 0x1f]!;
    }
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 0x1f]!;
  return out;
}

function rawSha256CidV1(content: Uint8Array): string {
  const digest = sha256(content);
  const cidBytes = new Uint8Array(4 + digest.length);
  cidBytes[0] = 0x01; // CIDv1
  cidBytes[1] = 0x55; // raw codec
  cidBytes[2] = 0x12; // sha2-256 multihash
  cidBytes[3] = 0x20; // 32-byte digest
  cidBytes.set(digest, 4);
  return `b${base32Encode(cidBytes)}`;
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

// Build a synthetic transaction that carries the record body under metadata
// label 309 and genuinely satisfies the integrity binding: the body commits
// to the auxiliary data via key 7, and the returned hash is the blake2b-256
// of the body bytes exactly as carried.
function buildTxCarrying(recordBody: Uint8Array | null): { txCbor: Uint8Array; txHash: string } {
  const aux: CanonicalCborValue =
    recordBody !== null
      ? (new Map<number, CanonicalCborValue>([
          [309, chunkRecordBody(recordBody)],
        ]) as unknown as CanonicalCborValue)
      : (new Map<number, CanonicalCborValue>([
          [674, new Map<string, CanonicalCborValue>([['msg', ['hello']]]) as CanonicalCborValue],
        ]) as unknown as CanonicalCborValue);
  const auxBytes = encodeCanonicalCbor(aux);
  const body = new Map<number, CanonicalCborValue>([
    [0, [[new Uint8Array(32), 0]]],
    [1, []],
    [2, 170000],
    [7, blake2b256(auxBytes)],
  ]) as unknown as CanonicalCborValue;
  const bodyBytes = encodeCanonicalCbor(body);
  const txCbor = encodeCanonicalCbor([
    body,
    new Map<number, CanonicalCborValue>() as unknown as CanonicalCborValue,
    true,
    aux,
  ] as readonly CanonicalCborValue[]);
  return { txCbor, txHash: bytesToHex(blake2b256(bodyBytes)) };
}

interface BuildFixtureOpts {
  readonly withRecordSig?: boolean;
  readonly tamperRecordSig?: boolean;
  readonly itemUris?: ReadonlyArray<string>;
  readonly itemContent?: Uint8Array;
  readonly sealedItem?: {
    readonly plaintext: Uint8Array;
    readonly recipientPub: Uint8Array;
  };
  readonly merkleCommit?: {
    readonly leaves: ReadonlyArray<Uint8Array>;
    readonly uris?: ReadonlyArray<string>;
  };
  readonly merkleOnly?: boolean;
}

interface Fixture {
  readonly txCbor: Uint8Array;
  readonly txHash: string;
  readonly record: PoeRecord;
  readonly recordSignerPub?: string;
  readonly ciphertext?: Uint8Array;
}

function buildFixture(opts: BuildFixtureOpts = {}): Fixture {
  const items: Record<string, unknown>[] = [];
  let ciphertext: Uint8Array | undefined;
  if (opts.sealedItem !== undefined) {
    const hashes = { 'sha2-256': sha256(opts.sealedItem.plaintext) };
    const wrap = eciesSealedPoeWrap({
      plaintext: opts.sealedItem.plaintext,
      hashes,
      recipientPublicKeys: [opts.sealedItem.recipientPub],
    });
    ciphertext = wrap.ciphertext;
    const env = wrap.envelope;
    const slots =
      env.kem === 'mlkem768x25519'
        ? env.slots.map((s) => ({ kem_ct: s.kem_ct, wrap: s.wrap }))
        : env.slots.map((s) => ({ epk: s.epk, wrap: s.wrap }));
    items.push({
      hashes,
      uris: opts.itemUris ?? [`ar://${ARWEAVE_TXID_1}`],
      enc: {
        scheme: env.scheme,
        aead: env.aead,
        kem: env.kem,
        nonce: env.nonce,
        slots,
        slots_mac: env.slots_mac,
      },
    });
  } else if (!opts.merkleOnly) {
    const content = opts.itemContent ?? new TextEncoder().encode('plain-content');
    items.push({
      hashes: { 'sha2-256': sha256(content) },
      ...(opts.itemUris !== undefined ? { uris: opts.itemUris } : {}),
    });
  }

  const recordValue: Record<string, unknown> = { v: 1 };
  if (items.length > 0) recordValue['items'] = items;

  if (opts.merkleCommit !== undefined) {
    recordValue['merkle'] = [
      {
        alg: 'rfc9162-sha256',
        root: merkleSha2256Root(opts.merkleCommit.leaves),
        leaf_count: opts.merkleCommit.leaves.length,
        ...(opts.merkleCommit.uris !== undefined ? { uris: opts.merkleCommit.uris } : {}),
      },
    ];
  }

  let recordSignerPub: string | undefined;
  if (opts.withRecordSig) {
    const seed = makeSeed(11);
    const pub = getPublicKeyEd25519({ seed });
    recordSignerPub = bytesToHex(pub);
    const tempRecord = PoeRecordSchema.parse(recordValue);
    const recordBodyCbor = encodeRecordBodyForSigning(tempRecord);
    let cose = coseSign1Label309Build({
      protectedHeader: new Map<number | string, unknown>([
        [1, -8],
        [4, pub],
      ]),
      unprotectedHeader: new Map(),
      recordBodyCbor,
      signerSecretKey: seed,
    });
    if (opts.tamperRecordSig) {
      cose = new Uint8Array(cose);
      cose[cose.length - 30] = (cose[cose.length - 30]! + 1) & 0xff;
    }
    recordValue['sigs'] = [{ cose_sign1: cose }];
  }

  const record = PoeRecordSchema.parse(recordValue);
  const recordBody = encodePoeRecord(record);
  const { txCbor, txHash } = buildTxCarrying(recordBody);
  return {
    txCbor,
    txHash,
    record,
    ...(recordSignerPub !== undefined && { recordSignerPub }),
    ...(ciphertext !== undefined && { ciphertext }),
  };
}

function koiosStub(txHash: string, txCbor: Uint8Array, confirmations: number): Route {
  return (u) => {
    if (u === `${KOIOS_MAINNET}/tx_cbor`) {
      return jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }]);
    }
    if (u === `${KOIOS_MAINNET}/tx_info`) {
      return jsonResponse([
        {
          tx_hash: txHash,
          num_confirmations: confirmations,
          tx_timestamp: 1700000000,
          absolute_slot: 99,
        },
      ]);
    }
    return undefined;
  };
}

describe('verifyTx — happy path', () => {
  it('record-sig (path 1, in-signature kid) → verdict valid, exit 0, schema-shaped report', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.exitCode).toBe(0);
    expect(r.profile).toBe('recipient-sealed');
    expect(r.network).toBe('cardano:mainnet');
    expect(r.confirmationDepth).toBe(50);
    expect(r.confirmationThreshold).toBe(15);
    expect(r.block_time).toBe(1700000000);
    expect(r.block_slot).toBe(99);
    expect(r.signatures).toEqual([
      {
        index: 0,
        verdict: 'valid',
        signerType: 'in-signature-kid',
        signerPub: fix.recordSignerPub,
      },
    ]);
    // One per-item entry, positionally aligned; a hash-only item with no
    // URIs has nothing to fetch and reports not_checked with no issue.
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    expect(r.merkle).toEqual([]);
    // Every error-severity rule of the severity contract: a valid verdict
    // coexists only with warning/info issues.
    expect(r.issues.every((i) => i.severity !== 'error')).toBe(true);
    // The audit trail records every outbound call of the run.
    expect(r.auditTrail.length).toBeGreaterThan(0);
    expect(r.auditTrail.every((c) => c.purpose === 'cardano')).toBe(true);
  });

  it('record-sig + sealed-PoE decryption end-to-end → verdict valid, plaintextHashOk', async () => {
    const recipientSecret = makeSeed(50);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('hello-world');
    const fix = buildFixture({
      withRecordSig: true,
      sealedItem: { plaintext, recipientPub },
    });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u) =>
        u === `https://arweave.net/${ARWEAVE_TXID_1}` ? bytesResponse(fix.ciphertext!) : undefined,
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.signatures?.[0]?.verdict).toBe('valid');
    expect(r.items).toEqual([
      { contentCheck: 'checked', decryption: { decrypted: true, plaintextHashOk: true } },
    ]);
  });

  it('plain item content fetched and matching → contentCheck checked', async () => {
    const content = new TextEncoder().encode('exact bytes');
    const fix = buildFixture({ itemContent: content, itemUris: [`ar://${ARWEAVE_TXID_1}`] });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u) => (u === `https://arweave.net/${ARWEAVE_TXID_1}` ? bytesResponse(content) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.items).toEqual([{ contentCheck: 'checked' }]);
  });
});

describe('verifyTx — four-state verdict mapping', () => {
  it('INSUFFICIENT_CONFIRMATIONS → verdict pending, exit 3, later steps skipped', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 5)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('pending');
    expect(r.exitCode).toBe(3);
    expect(r.issues.some((i) => i.code === 'INSUFFICIENT_CONFIRMATIONS')).toBe(true);
    // Below the threshold the pipeline halts before signature work.
    expect(r.signatures).toBeUndefined();
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
  });

  it('depth exactly at the threshold is NOT pending', async () => {
    const fix = buildFixture();
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 15)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
  });

  it('explicit threshold 1 lets 5 confirmations pass → verdict valid', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 5)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      confirmationDepthThreshold: 1,
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
  });

  it('PROVIDER_UNAVAILABLE (all explorers 503) → verdict unverifiable, exit 2', async () => {
    const stub: FetchOutbound = async () => emptyResponse(503);
    const r = await verifyTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.issues[0]?.code).toBe('PROVIDER_UNAVAILABLE');
  });

  it('TX_NOT_FOUND (definitive empty answer) → verdict unverifiable, exit 2', async () => {
    const stub = mkStubFetch([(u) => (u.endsWith('/tx_cbor') ? jsonResponse([]) : undefined)]);
    const r = await verifyTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.issues[0]?.code).toBe('TX_NOT_FOUND');
  });

  it('TX_INTEGRITY_MISMATCH (served bytes fail the binding) → unverifiable, exit 2', async () => {
    const fix = buildFixture();
    // Request a DIFFERENT hash than the served body computes to.
    const wrongHash = 'f'.repeat(64);
    const stub = mkStubFetch([koiosStub(wrongHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: wrongHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.issues[0]?.code).toBe('TX_INTEGRITY_MISMATCH');
  });

  it('METADATA_NOT_FOUND (bound tx without label 309) → verdict failed, exit 1', async () => {
    const { txCbor, txHash } = buildTxCarrying(null);
    const stub = mkStubFetch([koiosStub(txHash, txCbor, 50)]);
    const r = await verifyTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.issues[0]?.code).toBe('METADATA_NOT_FOUND');
  });

  it('SIGNATURE_INVALID → verdict failed, exit 1', async () => {
    const fix = buildFixture({ withRecordSig: true, tamperRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.signatures?.[0]?.verdict).toBe('invalid');
    expect(r.signatures?.[0]?.reason).toBe('SIGNATURE_INVALID');
    expect(r.issues.some((i) => i.code === 'SIGNATURE_INVALID')).toBe(true);
  });
});

describe('verifyTx — content integrity vs attribution vs availability', () => {
  it('ATTRIBUTABLE mismatching bytes (raw-CID binding verified) → URI_INTEGRITY_MISMATCH, failed', async () => {
    const committed = new TextEncoder().encode('committed bytes');
    const served = new TextEncoder().encode('different bytes');
    // The URI's CID addresses the SERVED bytes (binding verifies), but the
    // record commits to different bytes: record-attributable.
    const cid = rawSha256CidV1(served);
    const fix = buildFixture({ itemContent: committed, itemUris: [`ipfs://${cid}`] });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u) => (u.includes('/ipfs/') ? bytesResponse(served) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      ipfsGatewayChain: ['https://ipfs.example'],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.items).toEqual([{ contentCheck: 'mismatched' }]);
    expect(r.issues.some((i) => i.code === 'URI_INTEGRITY_MISMATCH')).toBe(true);
  });

  it('UNATTRIBUTABLE mismatching bytes (ar:// has no binding check) → provider warning + CONTENT_UNAVAILABLE → unverifiable', async () => {
    const committed = new TextEncoder().encode('committed bytes');
    const served = new TextEncoder().encode('garbage from a misbehaving gateway');
    const fix = buildFixture({ itemContent: committed, itemUris: [`ar://${ARWEAVE_TXID_1}`] });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u, o) => (o.purpose === 'arweave' ? bytesResponse(served) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    const provider = r.issues.filter((i) => i.code === 'URI_PROVIDER_INTEGRITY_MISMATCH');
    expect(provider.length).toBeGreaterThan(0);
    expect(provider.every((i) => i.severity === 'warning')).toBe(true);
    expect(r.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE')).toBe(true);
    expect(r.issues.some((i) => i.code === 'URI_INTEGRITY_MISMATCH')).toBe(false);
  });

  it('every gateway failing transiently → URI_FETCH_FAILED warnings + CONTENT_UNAVAILABLE → unverifiable', async () => {
    const fix = buildFixture({ itemUris: [`ar://${ARWEAVE_TXID_1}`] });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u, o) => (o.purpose === 'arweave' ? emptyResponse(500) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    expect(r.issues.some((i) => i.code === 'URI_FETCH_FAILED' && i.severity === 'warning')).toBe(
      true,
    );
    expect(r.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE')).toBe(true);
  });

  it('ceiling abort on a multi-URI claim → one CONTENT_FETCH_LIMIT_EXCEEDED ends the claim → unverifiable', async () => {
    const content = new Uint8Array(64).fill(0x61);
    const fix = buildFixture({
      itemContent: content,
      itemUris: [`ar://${ARWEAVE_TXID_1}`, `ar://${'B'.repeat(43)}`],
    });
    const storageUrls: string[] = [];
    const stub: FetchOutbound = async (url, opts) => {
      const routed = koiosStub(fix.txHash, fix.txCbor, 50)(url, opts);
      if (routed !== undefined) return routed;
      if (opts.purpose === 'arweave') {
        storageUrls.push(url);
        // Emulate the canonical egress primitive's incremental enforcement.
        const { BodyTooLargeError } = await import('../fetch/fetch-outbound');
        throw new BodyTooLargeError(url, opts.maxBytes ?? 0);
      }
      return emptyResponse(500);
    };
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      maxFetchBytes: 16,
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    // Every URI of a claim addresses the same bytes, so the first ceiling
    // abort ends the claim: exactly one availability issue, at the claim's
    // path, and the sibling URI is never fetched.
    const availability = r.issues.filter(
      (i) =>
        i.code === 'CONTENT_FETCH_LIMIT_EXCEEDED' ||
        i.code === 'CONTENT_UNAVAILABLE' ||
        i.code === 'URI_FETCH_FAILED',
    );
    expect(availability.map((i) => [i.code, i.path])).toEqual([
      ['CONTENT_FETCH_LIMIT_EXCEEDED', ['items', 0]],
    ]);
    expect(storageUrls).toEqual([`https://arweave.net/${ARWEAVE_TXID_1}`]);
  });
});

describe('verifyTx — Merkle commitments and the commitment floor', () => {
  const leaves = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];

  it('out-of-band leaves-list verifying → contentCheck checked, valid', async () => {
    const fix = buildFixture({ merkleOnly: true, merkleCommit: { leaves } });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const leavesBlob = encodeLeavesList({ leaves, root: merkleSha2256Root(leaves) });
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      merkleLeaves: { 0: leavesBlob },
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.merkle).toEqual([{ contentCheck: 'checked' }]);
  });

  it('merkle-only record with no obtainable leaves-list → MERKLE_LEAVES_UNAVAILABLE error → unverifiable (commitment floor)', async () => {
    const fix = buildFixture({ merkleOnly: true, merkleCommit: { leaves } });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.merkle).toEqual([{ contentCheck: 'not_checked' }]);
    const unavailable = r.issues.find((i) => i.code === 'MERKLE_LEAVES_UNAVAILABLE');
    expect(unavailable?.severity).toBe('error');
  });

  it('unavailable leaves-list BESIDE a verified content commitment → warning, record stays valid', async () => {
    const content = new TextEncoder().encode('verified sibling content');
    const fix = buildFixture({
      itemContent: content,
      itemUris: [`ar://${ARWEAVE_TXID_1}`],
      merkleCommit: { leaves },
    });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u, o) => (o.purpose === 'arweave' ? bytesResponse(content) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.items).toEqual([{ contentCheck: 'checked' }]);
    expect(r.merkle).toEqual([{ contentCheck: 'not_checked' }]);
    const unavailable = r.issues.find((i) => i.code === 'MERKLE_LEAVES_UNAVAILABLE');
    expect(unavailable?.severity).toBe('warning');
  });

  it('out-of-band leaves-list whose root disagrees → MERKLE_ROOT_MISMATCH → failed', async () => {
    const fix = buildFixture({ merkleOnly: true, merkleCommit: { leaves } });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const otherLeaves = [new Uint8Array(32).fill(9), new Uint8Array(32).fill(8)];
    const leavesBlob = encodeLeavesList({
      leaves: otherLeaves,
      root: merkleSha2256Root(otherLeaves),
    });
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      merkleLeaves: { 0: leavesBlob },
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.merkle).toEqual([{ contentCheck: 'mismatched' }]);
    expect(r.issues.some((i) => i.code === 'MERKLE_ROOT_MISMATCH')).toBe(true);
  });
});

describe('verifyTx — conformance profiles', () => {
  it("profile='core' reading a record with sigs emits OUT_OF_PROFILE_SKIPPED (info) and skips sig verification", async () => {
    const fix = buildFixture({ withRecordSig: true });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      profile: 'core',
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.profile).toBe('core');
    expect(r.signatures).toBeUndefined();
    expect(r.issues.some((i) => i.code === 'OUT_OF_PROFILE_SKIPPED' && i.severity === 'info')).toBe(
      true,
    );
  });

  it('public verifier (no credentials) never decrypts a sealed item nor fetches its ciphertext', async () => {
    // The public-verifier role: even at the highest profile, an empty keyring
    // means a sealed item's plaintext claim cannot be checked. The item must
    // report not_checked WITHOUT a decryption entry, no ciphertext fetch may
    // be issued, and the record's verdict is unaffected. Hosted verify
    // endpoints (which accept no decryption credentials by contract) rely on
    // exactly this branch.
    const recipientSecret = makeSeed(61);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('public-verifier-no-keys');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    let storageCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => {
        if (o.purpose === 'arweave' || o.purpose === 'ipfs') {
          storageCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      profile: 'recipient-sealed',
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    expect(storageCalls).toBe(0);
  });

  it("profile='signed' verifies sigs but never decrypts, even with credentials supplied", async () => {
    const recipientSecret = makeSeed(60);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('signed-no-decrypt');
    const fix = buildFixture({
      withRecordSig: true,
      sealedItem: { plaintext, recipientPub },
    });
    let storageCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => {
        if (o.purpose === 'arweave' || o.purpose === 'ipfs') {
          storageCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      profile: 'signed',
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.signatures?.[0]?.verdict).toBe('valid');
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    expect(storageCalls).toBe(0);
  });
});

describe('verifyTx — service independence (denyHosts)', () => {
  it('denied explorer host → SERVICE_INDEPENDENCE_VIOLATION, verdict failed', async () => {
    const stub: FetchOutbound = async () => bytesResponse(new Uint8Array(0));
    const r = await verifyTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET],
      denyHosts: ['api.koios.rest'],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.issues[0]?.code).toBe('SERVICE_INDEPENDENCE_VIOLATION');
    // The refused call is still recorded in the audit trail (status null).
    expect(r.auditTrail.some((c) => c.url.includes('api.koios.rest') && c.status === null)).toBe(
      true,
    );
  });

  it('denied storage gateway → per-attempt SERVICE_INDEPENDENCE_VIOLATION at the uris path, claim unchecked, verdict failed', async () => {
    const content = new TextEncoder().encode('content');
    const fix = buildFixture({ itemContent: content, itemUris: [`ar://${ARWEAVE_TXID_1}`] });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => (o.purpose === 'arweave' ? bytesResponse(content) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      arweaveGatewayChain: ['https://arweave.net'],
      denyHosts: ['arweave.net'],
      fetchOutbound: stub,
    });
    // A content-path deny-hit is per-attempt evidence at the claim's uris[]
    // path — the pipeline continues (the claim ends unchecked), but the
    // error-severity violation still forces the verdict to failed.
    expect(r.verdict).toBe('failed');
    const violation = r.issues.find((i) => i.code === 'SERVICE_INDEPENDENCE_VIOLATION');
    expect(violation?.path).toEqual(['items', 0, 'uris', 0]);
    expect(r.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE')).toBe(true);
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
  });

  it('one deny-listed URI beside a good URI → violation recorded, content still verified from the good source', async () => {
    const content = new TextEncoder().encode('dual-uri content');
    const cid = rawSha256CidV1(content);
    const fix = buildFixture({
      itemContent: content,
      itemUris: [`ar://${ARWEAVE_TXID_1}`, `ipfs://${cid}`],
    });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) =>
        o.purpose === 'arweave' || o.purpose === 'ipfs' ? bytesResponse(content) : undefined,
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      arweaveGatewayChain: ['https://arweave.net'],
      ipfsGatewayChain: ['https://ipfs.example'],
      denyHosts: ['arweave.net'],
      fetchOutbound: stub,
    });
    // The claim is satisfied by the second source, but the violation is
    // error-severity, record-attributable-class evidence: verdict failed.
    expect(r.items).toEqual([{ contentCheck: 'checked' }]);
    const violation = r.issues.find((i) => i.code === 'SERVICE_INDEPENDENCE_VIOLATION');
    expect(violation?.path).toEqual(['items', 0, 'uris', 0]);
    expect(r.verdict).toBe('failed');
  });
});

describe('verifyTx — sealed-PoE decryption failure modes', () => {
  it('wrong recipient key → WRONG_RECIPIENT_KEY, verdict failed', async () => {
    const recipientSecret = makeSeed(70);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('top-secret');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    const wrongSecret = makeSeed(99);
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (u) =>
        u === `https://arweave.net/${ARWEAVE_TXID_1}` ? bytesResponse(fix.ciphertext!) : undefined,
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: wrongSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.items[0]?.decryption).toEqual({ decrypted: false, code: 'WRONG_RECIPIENT_KEY' });
    expect(r.items[0]?.contentCheck).toBe('not_checked');
  });

  it('passphrase supplied against a slots-path item → WRONG_DECRYPTION_INPUT_SHAPE', async () => {
    const recipientSecret = makeSeed(71);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const fix = buildFixture({
      sealedItem: { plaintext: new TextEncoder().encode('x'), recipientPub },
    });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ passphrase: 'not applicable here' }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.items[0]?.decryption).toEqual({
      decrypted: false,
      code: 'WRONG_DECRYPTION_INPUT_SHAPE',
    });
  });

  it('ciphertext unobtainable → CIPHERTEXT_UNAVAILABLE → unverifiable', async () => {
    const recipientSecret = makeSeed(80);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('content-unavailable');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => (o.purpose === 'arweave' ? emptyResponse(500) : undefined),
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.items[0]?.decryption).toEqual({ decrypted: false, code: 'CIPHERTEXT_UNAVAILABLE' });
  });

  it('tampered ciphertext supplied out-of-band (attributable) → TAMPERED_CIPHERTEXT → failed', async () => {
    const recipientSecret = makeSeed(81);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('tamper-me');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    const tampered = new Uint8Array(fix.ciphertext!);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1]! + 1) & 0xff;
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      ciphertextBytes: { 0: tampered },
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('failed');
    expect(r.items[0]?.contentCheck).toBe('mismatched');
    expect(r.items[0]?.decryption).toEqual({ decrypted: false, code: 'TAMPERED_CIPHERTEXT' });
    expect(r.issues.some((i) => i.code === 'TAMPERED_CIPHERTEXT')).toBe(true);
  });

  it('out-of-band ciphertextBytes take precedence over uris[] (no fetch issued)', async () => {
    const recipientSecret = makeSeed(82);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('oob-bytes');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    let storageCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => {
        if (o.purpose === 'arweave' || o.purpose === 'ipfs') {
          storageCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      ciphertextBytes: { 0: fix.ciphertext! },
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(storageCalls).toBe(0);
  });
});

describe('verifyTx — fetchContent:false (the offline master switch)', () => {
  it('suppresses every outbound content fetch; claims report not_checked', async () => {
    const recipientSecret = makeSeed(83);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('offline-no-fetch');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    let storageCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => {
        if (o.purpose === 'arweave' || o.purpose === 'ipfs') {
          storageCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      fetchContent: false,
      fetchOutbound: stub,
    });
    expect(storageCalls).toBe(0);
    expect(r.items[0]?.contentCheck).toBe('not_checked');
    expect(r.items[0]?.decryption?.code).toBe('CIPHERTEXT_UNAVAILABLE');
    expect(r.auditTrail.every((c) => c.purpose === 'cardano')).toBe(true);
  });

  it('still decrypts offline from out-of-band ciphertextBytes', async () => {
    const recipientSecret = makeSeed(84);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const plaintext = new TextEncoder().encode('offline-oob');
    const fix = buildFixture({ sealedItem: { plaintext, recipientPub } });
    let storageCalls = 0;
    const stub = mkStubFetch([
      koiosStub(fix.txHash, fix.txCbor, 50),
      (_u, o) => {
        if (o.purpose === 'arweave' || o.purpose === 'ipfs') {
          storageCalls += 1;
          return bytesResponse(fix.ciphertext!);
        }
        return undefined;
      },
    ]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      decryption: [{ recipientSecretKey: recipientSecret }],
      ciphertextBytes: { 0: fix.ciphertext! },
      fetchContent: false,
      fetchOutbound: stub,
    });
    expect(storageCalls).toBe(0);
    expect(r.verdict).toBe('valid');
    expect(r.items[0]?.decryption).toEqual({ decrypted: true, plaintextHashOk: true });
  });

  it('plain-item claims and merkle commitments report not_checked offline with no availability issue', async () => {
    const leaves = [new Uint8Array(32).fill(3)];
    const fix = buildFixture({
      itemUris: [`ar://${ARWEAVE_TXID_1}`],
      merkleCommit: { leaves, uris: [`ar://${ARWEAVE_TXID_1}`] },
    });
    const stub = mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]);
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchContent: false,
      fetchOutbound: stub,
    });
    expect(r.verdict).toBe('valid');
    expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
    expect(r.merkle).toEqual([{ contentCheck: 'not_checked' }]);
    expect(r.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE')).toBe(false);
    expect(r.issues.some((i) => i.code === 'MERKLE_LEAVES_UNAVAILABLE')).toBe(false);
  });
});

describe('verifyResolved — caller-supplied record bytes + block-info tuple', () => {
  it('runs the pipeline from structural validation onward', async () => {
    const fix = buildFixture({ withRecordSig: true });
    const recordBody = encodePoeRecord(fix.record);
    const r = await verifyResolved({
      txHash: fix.txHash,
      metadataCbor: recordBody,
      confirmationDepth: 42,
      blockTime: 1700000123,
      blockSlot: 777,
      fetchContent: false,
      fetchOutbound: async () => {
        throw new Error('offline run must not fetch');
      },
    });
    expect(r.verdict).toBe('valid');
    expect(r.confirmationDepth).toBe(42);
    expect(r.block_time).toBe(1700000123);
    expect(r.block_slot).toBe(777);
    expect(r.signatures?.[0]?.verdict).toBe('valid');
    expect(r.auditTrail).toEqual([]);
  });

  it('structural rejection → verdict failed with the validator issue list', async () => {
    const r = await verifyResolved({
      txHash: '0'.repeat(64),
      metadataCbor: new TextEncoder().encode('not cbor at all'),
      confirmationDepth: 42,
      blockTime: 1700000123,
    });
    expect(r.verdict).toBe('failed');
    expect(r.exitCode).toBe(1);
    expect(r.issues.length).toBeGreaterThan(0);
    expect(r.items).toEqual([]);
  });

  it('a caller-supplied confirmation depth below 1 is a typed input error, not a report outcome', async () => {
    // A transaction in a block has depth = tip − block + 1 >= 1 by
    // definition; a caller asserting less contradicts its own block-info
    // tuple, so no report is produced.
    const fix = buildFixture({});
    const base = {
      txHash: fix.txHash,
      metadataCbor: encodePoeRecord(fix.record),
      blockTime: 1700000123,
      fetchContent: false,
    };
    await expect(verifyResolved({ ...base, confirmationDepth: 0 })).rejects.toThrow(RangeError);
    await expect(verifyResolved({ ...base, confirmationDepth: 1.5 })).rejects.toThrow(RangeError);
  });
});

describe('inconsistent explorer snapshots never fabricate a confirmation depth', () => {
  function koiosHeightStub(fix: Fixture, blockHeight: number, tipHeight: number): Route {
    return (u) => {
      if (u === `${KOIOS_MAINNET}/tx_cbor`) {
        return jsonResponse([{ tx_hash: fix.txHash, cbor: bytesToHex(fix.txCbor) }]);
      }
      if (u === `${KOIOS_MAINNET}/tx_info`) {
        return jsonResponse([
          {
            tx_hash: fix.txHash,
            block_height: blockHeight,
            tx_timestamp: 1700000000,
            absolute_slot: 99,
          },
        ]);
      }
      if (u === `${KOIOS_MAINNET}/tip`) {
        return jsonResponse([{ block_height: tipHeight }]);
      }
      return undefined;
    };
  }

  it('a provider contradicting its own tip ends the run unverifiable with NO confirmationDepth key', async () => {
    const fix = buildFixture({});
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: mkStubFetch([koiosHeightStub(fix, 100, 99)]),
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.exitCode).toBe(2);
    expect(r.issues.some((i) => i.code === 'PROVIDER_UNAVAILABLE')).toBe(true);
    // No chain facts were resolved, so the report carries none — a depth of
    // 1 fabricated from a self-contradicting snapshot could satisfy a
    // threshold-1 confirmation gate.
    expect('confirmationDepth' in r).toBe(false);
    expect('block_time' in r).toBe(false);
  });

  it('a consistent tip-block snapshot resolves depth exactly 1 and passes a threshold-1 gate', async () => {
    const fix = buildFixture({});
    const r = await verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      confirmationDepthThreshold: 1,
      fetchOutbound: mkStubFetch([koiosHeightStub(fix, 100, 100)]),
    });
    expect(r.verdict).toBe('valid');
    expect(r.confirmationDepth).toBe(1);
  });
});

describe('unsupported signature algorithms — exactly one SIGNATURE_UNSUPPORTED per entry', () => {
  // Sign genuinely with Ed25519 but declare `alg` as something this verifier
  // does not verify: -19 is registered in the signature-algorithm registry
  // but unimplemented, -7 (ES256) is outside the registry entirely.
  function buildFixtureWithSigAlg(alg: number): Fixture {
    const seed = makeSeed(13);
    const pub = getPublicKeyEd25519({ seed });
    const base: Record<string, unknown> = {
      v: 1,
      items: [{ hashes: { 'sha2-256': sha256(new TextEncoder().encode('alg-test')) } }],
    };
    const cose = coseSign1Label309Build({
      protectedHeader: new Map<number | string, unknown>([
        [1, alg],
        [4, pub],
      ]),
      unprotectedHeader: new Map(),
      recordBodyCbor: encodeRecordBodyForSigning(PoeRecordSchema.parse(base)),
      signerSecretKey: seed,
    });
    const record = PoeRecordSchema.parse({ ...base, sigs: [{ cose_sign1: cose }] });
    const { txCbor, txHash } = buildTxCarrying(encodePoeRecord(record));
    return { txCbor, txHash, record };
  }

  async function verifyWithAlg(alg: number) {
    const fix = buildFixtureWithSigAlg(alg);
    return verifyTx({
      txHash: fix.txHash,
      cardanoGatewayChain: [KOIOS_MAINNET],
      fetchOutbound: mkStubFetch([koiosStub(fix.txHash, fix.txCbor, 50)]),
    });
  }

  it('registered-but-unimplemented alg (-19): one info issue at sigs.0, verdict still valid', async () => {
    const r = await verifyWithAlg(-19);
    const unsupported = r.issues.filter((i) => i.code === 'SIGNATURE_UNSUPPORTED');
    expect(unsupported).toHaveLength(1);
    expect(unsupported[0]).toMatchObject({ path: ['sigs', 0], severity: 'info' });
    expect(r.signatures?.[0]?.verdict).toBe('unsupported');
    // info never fails the record: the content claim stands on its own.
    expect(r.verdict).toBe('valid');
    expect(r.exitCode).toBe(0);
  });

  it('unregistered alg (-7): validator + verifier both conclude unsupported, still one issue', async () => {
    const r = await verifyWithAlg(-7);
    const unsupported = r.issues.filter((i) => i.code === 'SIGNATURE_UNSUPPORTED');
    expect(unsupported).toHaveLength(1);
    expect(unsupported[0]).toMatchObject({ path: ['sigs', 0], severity: 'info' });
    expect(r.signatures?.[0]?.verdict).toBe('unsupported');
    expect(r.verdict).toBe('valid');
  });
});

describe('content-gateway redirects are never followed', () => {
  it('302 toward a deny-listed target is a failed attempt, not a followed hop', async () => {
    const fix = buildFixture({ itemUris: [`ar://${ARWEAVE_TXID_1}`] });
    // The run uses the real default transport with the platform fetch stubbed:
    // the gateway answers a redirect pointing INTO the deny-listed loopback.
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/steal' } }),
      );
    try {
      const r = await verifyResolved({
        txHash: fix.txHash,
        metadataCbor: encodePoeRecord(fix.record),
        confirmationDepth: 50,
        blockTime: 1700000123,
        arweaveGatewayChain: ['https://gw.test'],
        denyHosts: ['localhost', '127.0.0.1'],
      });
      // The redirect target was never contacted: one outbound call, to the
      // gateway only.
      expect(fetchSpy).toHaveBeenCalledOnce();
      expect(String(fetchSpy.mock.calls[0]![0])).toBe(`https://gw.test/${ARWEAVE_TXID_1}`);
      // The attempt is recorded as failed with its real 3xx status…
      expect(r.auditTrail).toEqual([expect.objectContaining({ status: 302 })]);
      // …and classified as availability: the deny-listed host was never
      // reached, so no service-independence violation is raised.
      expect(r.issues.some((i) => i.code === 'SERVICE_INDEPENDENCE_VIOLATION')).toBe(false);
      expect(r.issues.some((i) => i.code === 'URI_FETCH_FAILED')).toBe(true);
      expect(r.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE' && i.severity === 'error')).toBe(
        true,
      );
      expect(r.items).toEqual([{ contentCheck: 'not_checked' }]);
      expect(r.verdict).toBe('unverifiable');
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
