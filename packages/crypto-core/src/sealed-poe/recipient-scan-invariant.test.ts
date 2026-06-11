// The recipient-scan invariant: given ONLY (a) a recipient's seed-derived
// private key and (b) the on-chain record bytes — the canonical-CBOR record
// body whose item carries the `enc` envelope (slots, slots_mac, nonce, kem,
// aead) — the implementation determines that the sealed record is addressed
// to that key AND recovers the CEK, with no ciphertext available at all.
//
// This is the contract an inbox feed-scan runs on: it walks a public records
// feed of bare record bodies and trial-decrypts each one client-side; the
// off-chain ciphertext is fetched only later, when the user opens a matched
// record. The tests below therefore never hand the scan the ciphertext, and a
// stubbed global fetch proves the whole path performs zero network I/O.

import { sha256 } from '@noble/hashes/sha2.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decodeCanonicalCbor, encodeCanonicalCbor } from '../cbor/canonical';
import type { CanonicalCborValue } from '../cbor/canonical';
import {
  deriveMlKem768X25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
} from '../seed-derive/derive';

import { sealedEnvelopeFromParsed } from './envelope-from-parsed';
import type { ParsedEnvelopeShape, ParsedSlotShape } from './envelope-from-parsed';
import type { ItemHashes } from './transcript';
import { eciesSealedPoeTrialDecrypt } from './unwrap';
import type { TrialDecryptOnlyResult } from './unwrap';
import { eciesSealedPoeWrap } from './wrap';
import type { SealedEnvelope } from './wrap';

function fillBytes(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function patternBytes(start: number, length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// On-chain record body construction (canonical CBOR, the bytes the chunk-array
// transport carries under metadata label 309).
// ---------------------------------------------------------------------------

function encodeSealedRecord(hashes: ItemHashes, envelope: SealedEnvelope): Uint8Array {
  const slots: CanonicalCborValue =
    envelope.kem === 'x25519'
      ? envelope.slots.map((s) => ({ epk: s.epk, wrap: s.wrap }))
      : envelope.slots.map((s) => ({ kem_ct: s.kem_ct, wrap: s.wrap }));
  return encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: hashes as { readonly [key: string]: Uint8Array },
        enc: {
          scheme: envelope.scheme,
          aead: envelope.aead,
          kem: envelope.kem,
          nonce: envelope.nonce,
          slots,
          slots_mac: envelope.slots_mac,
        },
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// The scan itself: record bytes + one private key in, trial-decrypt result
// out. Decoded CBOR maps are read tolerantly (Map or plain object) so the
// walk asserts the wire shape, not the decoder's container choice.
// ---------------------------------------------------------------------------

function mapGet(container: unknown, key: string): unknown {
  if (container instanceof Map) return container.get(key) as unknown;
  if (typeof container === 'object' && container !== null) {
    return (container as Record<string, unknown>)[key];
  }
  throw new Error(`expected a CBOR map while reading ${key}`);
}

function mapEntries(container: unknown): Array<[string, unknown]> {
  if (container instanceof Map) {
    return Array.from(container.entries() as Iterable<[string, unknown]>);
  }
  if (typeof container === 'object' && container !== null) {
    return Object.entries(container);
  }
  throw new Error('expected a CBOR map');
}

function asBytes(value: unknown, what: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`expected bytes for ${what}`);
  return value;
}

function scanRecordBytes(recordBytes: Uint8Array, secretKey: Uint8Array): TrialDecryptOnlyResult {
  const record = decodeCanonicalCbor(recordBytes);
  const items = mapGet(record, 'items');
  if (!Array.isArray(items) || items.length !== 1) throw new Error('expected one record item');
  const item: unknown = items[0];

  const hashes: ItemHashes = Object.fromEntries(
    mapEntries(mapGet(item, 'hashes')).map(([alg, digest]) => [
      alg,
      asBytes(digest, `hashes[${alg}]`),
    ]),
  );

  const enc = mapGet(item, 'enc');
  const rawSlots = mapGet(enc, 'slots');
  if (!Array.isArray(rawSlots)) throw new Error('expected enc.slots to be an array');
  const slots: ParsedSlotShape[] = rawSlots.map((slot: unknown) => ({
    epk: mapGet(slot, 'epk') as Uint8Array | undefined,
    kem_ct: mapGet(slot, 'kem_ct') as Uint8Array | undefined,
    wrap: mapGet(slot, 'wrap') as Uint8Array | undefined,
  }));
  const parsed: ParsedEnvelopeShape = {
    scheme: mapGet(enc, 'scheme'),
    aead: mapGet(enc, 'aead') as string | undefined,
    kem: mapGet(enc, 'kem') as string | undefined,
    nonce: mapGet(enc, 'nonce') as Uint8Array | undefined,
    slots,
    slots_mac: mapGet(enc, 'slots_mac') as Uint8Array | undefined,
  };

  const envelope = sealedEnvelopeFromParsed(parsed);
  if (envelope === null) throw new Error('record does not carry a sealed-recipient envelope');
  return eciesSealedPoeTrialDecrypt({ envelope, hashes, recipientSecretKeys: [secretKey] });
}

// ---------------------------------------------------------------------------
// Fixtures: a two-recipient record per KEM, with the scanning recipient in the
// SECOND slot so the scan demonstrably walks past a foreign slot. Wrap inputs
// are pinned (deterministic ephemerals, CEK, nonce, no shuffle) so the
// recovered CEK can be asserted byte-for-byte.
// ---------------------------------------------------------------------------

const RECIPIENT_SEED = fillBytes(0x42, 32);
const OTHER_SEED = fillBytes(0x43, 32);
const STRANGER_SEED = fillBytes(0x44, 32);

const PLAINTEXT = new TextEncoder().encode('feed-scan invariant payload');
const HASHES: ItemHashes = { 'sha2-256': sha256(PLAINTEXT) };
const CEK = patternBytes(0xc0, 32);

let fetchCalls = 0;

beforeEach(() => {
  fetchCalls = 0;
  vi.stubGlobal('fetch', () => {
    fetchCalls += 1;
    throw new Error('the recipient scan must not perform network I/O');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('recipient-scan invariant — x25519', () => {
  const recipient = deriveX25519KeypairFromSeed(RECIPIENT_SEED);
  const other = deriveX25519KeypairFromSeed(OTHER_SEED);
  // Only the envelope survives into the test: the wrap's ciphertext is
  // deliberately discarded, so nothing below can touch it.
  const { envelope } = eciesSealedPoeWrap({
    plaintext: PLAINTEXT,
    hashes: HASHES,
    recipientPublicKeys: [other.publicKey, recipient.publicKey],
    cek: CEK,
    nonce: patternBytes(0x10, 24),
    ephemeralSecrets: [patternBytes(0x20, 32), patternBytes(0x60, 32)],
    skipShuffle: true,
  });
  const recordBytes = encodeSealedRecord(HASHES, envelope);

  it('seed → derived key → on-chain bytes match → CEK, with no ciphertext', () => {
    const scanned = deriveX25519KeypairFromSeed(RECIPIENT_SEED);
    const result = scanRecordBytes(recordBytes, scanned.secretKey);
    expect(result.kind).toBe('match');
    if (result.kind !== 'match') return;
    expect(result.slotIdx).toBe(1);
    expect(bytesToHex(result.cek)).toBe(bytesToHex(CEK));
    expect(fetchCalls).toBe(0);
  });

  it('a non-recipient seed scans the same bytes to no-match', () => {
    const stranger = deriveX25519KeypairFromSeed(STRANGER_SEED);
    const result = scanRecordBytes(recordBytes, stranger.secretKey);
    expect(result.kind).toBe('no_match');
    expect(fetchCalls).toBe(0);
  });
});

describe('recipient-scan invariant — mlkem768x25519', () => {
  const recipient = deriveMlKem768X25519KeypairFromSeed(RECIPIENT_SEED);
  const other = deriveMlKem768X25519KeypairFromSeed(OTHER_SEED);
  const { envelope } = eciesSealedPoeWrap({
    plaintext: PLAINTEXT,
    hashes: HASHES,
    recipientPublicKeys: [other.publicKey, recipient.publicKey],
    kem: 'mlkem768x25519',
    cek: CEK,
    nonce: patternBytes(0x30, 24),
    eseeds: [patternBytes(0x21, 64), patternBytes(0x61, 64)],
    skipShuffle: true,
  });
  const recordBytes = encodeSealedRecord(HASHES, envelope);

  it('seed → derived key → on-chain bytes match → CEK, with no ciphertext', () => {
    const scanned = deriveMlKem768X25519KeypairFromSeed(RECIPIENT_SEED);
    const result = scanRecordBytes(recordBytes, scanned.secretSeed);
    expect(result.kind).toBe('match');
    if (result.kind !== 'match') return;
    expect(result.slotIdx).toBe(1);
    expect(bytesToHex(result.cek)).toBe(bytesToHex(CEK));
    expect(fetchCalls).toBe(0);
  });

  it('a non-recipient seed scans the same bytes to no-match', () => {
    const stranger = deriveMlKem768X25519KeypairFromSeed(STRANGER_SEED);
    const result = scanRecordBytes(recordBytes, stranger.secretSeed);
    expect(result.kind).toBe('no_match');
    expect(fetchCalls).toBe(0);
  });
});
