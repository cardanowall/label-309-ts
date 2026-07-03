// Tests for the record-size estimator: pinned cross-SDK parity literals, the
// upper-bound property against the real canonical-CBOR encoder, canonical
// header-width boundaries, the fixed path-1 COSE_Sign1 constant, tightness
// near the ceiling, and the near-ceiling non-rejection regression.

import { describe, expect, it } from 'vitest';

import { eciesSealedPoeWrap } from '@cardanowall/crypto-core/sealed-poe';
import { merkleSha2256Root, MERKLE_ALG_ID } from '@cardanowall/crypto-core/hash';
import { mlkem768x25519Keygen, x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { getPublicKeyEd25519, signEd25519 } from '@cardanowall/crypto-core/sig';
import {
  encodePoeRecord,
  type EncryptionEnvelope,
  type PoeRecord,
} from '@cardanowall/poe-standard';

import { assembleCoseSign1, prepareSigStructure } from '../client/off-host-sign';
import { estimateRecordBytes, MAX_RECORD_BYTES, type RecordShape } from './index';

// 48-character `ar://` URI shared with the sibling SDKs' parity tables.
const URI = 'ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

function own(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(src.length));
  out.set(src);
  return out;
}

function digest(fill: number): Uint8Array<ArrayBuffer> {
  return own(new Uint8Array(32).fill(fill));
}

/** Sign a record path-1 with a deterministic in-memory Ed25519 key. */
function signRecord(record: PoeRecord): PoeRecord {
  const seed = new Uint8Array(32).fill(0x42);
  const signerPubkey = getPublicKeyEd25519({ seed });
  const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
  const signature = signEd25519({ seed, message: sigStructureBytes });
  const { sigEntry } = assembleCoseSign1({ record, signerPubkey, signature });
  return { ...record, sigs: [sigEntry] };
}

/**
 * Seal a plaintext to `recipients` and project the envelope into the record's
 * wire shape (mirrors the mapping the sealed publish helper performs).
 */
function sealedEnvelope(
  hashes: Record<string, Uint8Array>,
  recipients: Uint8Array[],
  kem: 'x25519' | 'mlkem768x25519',
): EncryptionEnvelope {
  const sealed = eciesSealedPoeWrap({
    plaintext: new TextEncoder().encode('estimate-bound plaintext'),
    hashes,
    recipientPublicKeys: recipients,
    kem,
  });
  const env = sealed.envelope;
  const slots =
    env.kem === 'mlkem768x25519'
      ? env.slots.map((s) => ({ kem_ct: own(s.kem_ct), wrap: own(s.wrap) }))
      : env.slots.map((s) => ({ epk: own(s.epk), wrap: own(s.wrap) }));
  return {
    scheme: 1,
    aead: env.aead,
    kem: env.kem,
    nonce: own(env.nonce),
    slots,
    slots_mac: own(env.slots_mac),
  };
}

function xwingRecipients(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, i) => {
    const seed = new Uint8Array(32).fill(i + 1);
    return mlkem768x25519Keygen(seed).publicKey;
  });
}

function x25519Recipients(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, i) =>
    x25519PublicKey({ secretKey: new Uint8Array(32).fill(i + 1) }),
  );
}

/** The core property: the estimate is an upper bound on the real encoding. */
function expectUpperBound(shape: RecordShape, record: PoeRecord): void {
  const actual = encodePoeRecord(record).length;
  const estimate = estimateRecordBytes(shape);
  expect(estimate).toBeGreaterThanOrEqual(actual);
}

describe('estimateRecordBytes — cross-SDK parity table', () => {
  it('T1: hash-only single item (sha2-256), unsigned → 79', () => {
    expect(estimateRecordBytes({ items: [{ hashAlgs: ['sha2-256'] }] })).toBe(79);
  });

  it('T2: dual-hash item, signed + supersedes → 299', () => {
    expect(
      estimateRecordBytes({
        items: [{ hashAlgs: ['sha2-256', 'blake2b-256'] }],
        signed: true,
        supersedes: true,
      }),
    ).toBe(299);
  });

  it('T3: dual-hash item + one 48-char ar:// URI → 181', () => {
    expect(
      estimateRecordBytes({ items: [{ hashAlgs: ['sha2-256', 'blake2b-256'], uris: [URI] }] }),
    ).toBe(181);
  });

  it('T4: signed merkle (rfc9162-sha256) + one 48-char URI, no items → 292', () => {
    expect(
      estimateRecordBytes({ merkle: { alg: 'rfc9162-sha256', uris: [URI] }, signed: true }),
    ).toBe(292);
  });

  it('T5: sealed x25519, 2 recipients, sha2-256 + URI → 472', () => {
    expect(
      estimateRecordBytes({
        items: [{ hashAlgs: ['sha2-256'], uris: [URI], recipientCount: 2, kem: 'x25519' }],
      }),
    ).toBe(472);
  });

  it('T6: sealed X-Wing, 11 recipients, sha2-256 + URI, signed → 13459', () => {
    expect(
      estimateRecordBytes({
        items: [{ hashAlgs: ['sha2-256'], uris: [URI], recipientCount: 11, kem: 'mlkem768x25519' }],
        signed: true,
      }),
    ).toBe(13459);
  });
});

describe('estimateRecordBytes — upper bound against the real encoder', () => {
  it('bounds a hash-only single-alg record', () => {
    const shape: RecordShape = { items: [{ hashAlgs: ['sha2-256'] }] };
    const record: PoeRecord = { v: 1, items: [{ hashes: { 'sha2-256': digest(0xab) } }] };
    expectUpperBound(shape, record);
  });

  it('bounds a dual-alg signed record with supersedes', () => {
    const shape: RecordShape = {
      items: [{ hashAlgs: ['sha2-256', 'blake2b-256'] }],
      signed: true,
      supersedes: true,
    };
    const record: PoeRecord = signRecord({
      v: 1,
      items: [{ hashes: { 'sha2-256': digest(0xab), 'blake2b-256': digest(0xcd) } }],
      supersedes: digest(0x22),
    });
    expectUpperBound(shape, record);
  });

  it('bounds a public record with a content URI', () => {
    const shape: RecordShape = {
      items: [{ hashAlgs: ['sha2-256', 'blake2b-256'], uris: [URI] }],
    };
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': digest(0xab), 'blake2b-256': digest(0xcd) }, uris: [URI] }],
    };
    expectUpperBound(shape, record);
  });

  it('bounds a multi-item public record (every item summed)', () => {
    const shapes = [];
    const items = [];
    for (let i = 0; i < 4; i++) {
      const uri = `ar://item-${i}-0123456789abcdefghijklmnopqrstuvwxyzAB`;
      shapes.push({ hashAlgs: ['sha2-256', 'blake2b-256'], uris: [uri] });
      items.push({
        hashes: { 'sha2-256': digest(i), 'blake2b-256': digest(i + 1) },
        uris: [uri],
      });
    }
    expectUpperBound({ items: shapes }, { v: 1, items });
  });

  it('bounds a record carrying BOTH items[] and merkle[] (additive peers)', () => {
    const itemUri = 'ar://content-item-uri-0123456789abcdefghijklmnop';
    const leavesUri = 'ar://leaves-list-uri-0123456789abcdefghijklmnopq';
    const leaves = [digest(0), digest(1), digest(2)];
    const root = own(merkleSha2256Root(leaves));
    const shape: RecordShape = {
      items: [{ hashAlgs: ['sha2-256', 'blake2b-256'], uris: [itemUri] }],
      merkle: { alg: MERKLE_ALG_ID, uris: [leavesUri] },
    };
    const record: PoeRecord = {
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': digest(0xab), 'blake2b-256': digest(0xcd) },
          uris: [itemUri],
        },
      ],
      merkle: [{ alg: MERKLE_ALG_ID, root, leaf_count: leaves.length, uris: [leavesUri] }],
    };
    expectUpperBound(shape, record);
  });

  it('bounds a sealed x25519 record with many recipients', () => {
    const recipients = x25519Recipients(5);
    const uri = 'ar://sealed-ciphertext-tx-id-000000000000000000000000000';
    const hashes = { 'sha2-256': digest(0x07) };
    const shape: RecordShape = {
      items: [
        { hashAlgs: ['sha2-256'], uris: [uri], recipientCount: recipients.length, kem: 'x25519' },
      ],
    };
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes, uris: [uri], enc: sealedEnvelope(hashes, recipients, 'x25519') }],
    };
    expectUpperBound(shape, record);
  });

  it('bounds a sealed X-Wing signed record', () => {
    const recipients = xwingRecipients(3);
    const uri = 'ar://xwing-ct';
    const hashes = { 'sha2-256': digest(0x09) };
    const shape: RecordShape = {
      items: [
        {
          hashAlgs: ['sha2-256'],
          uris: [uri],
          recipientCount: recipients.length,
          kem: 'mlkem768x25519',
        },
      ],
      signed: true,
    };
    const record: PoeRecord = signRecord({
      v: 1,
      items: [{ hashes, uris: [uri], enc: sealedEnvelope(hashes, recipients, 'mlkem768x25519') }],
    });
    expectUpperBound(shape, record);
  });

  it('bounds a merkle-only record', () => {
    const leaves = [digest(0), digest(1), digest(2), digest(3)];
    const root = own(merkleSha2256Root(leaves));
    const uri = 'ar://leaves-list-tx';
    const shape: RecordShape = { merkle: { alg: MERKLE_ALG_ID, uris: [uri] } };
    const record: PoeRecord = {
      v: 1,
      merkle: [{ alg: MERKLE_ALG_ID, root, leaf_count: leaves.length, uris: [uri] }],
    };
    expectUpperBound(shape, record);
  });
});

describe('estimateRecordBytes — canonical header-width boundaries', () => {
  // The per-URI charge is header + payload; growing a URI by one byte across a
  // canonical header boundary must grow the estimate by 1 (payload) + the
  // header-width step. This pins the 23→24 (1→2 byte header) and 255→256
  // (2→3 byte header) boundaries behaviourally.
  function estimateWithUriLength(len: number): number {
    return estimateRecordBytes({ items: [{ hashAlgs: ['sha2-256'], uris: ['x'.repeat(len)] }] });
  }

  it('charges 1-byte headers up to 23, stepping to 2 bytes at 24', () => {
    expect(estimateWithUriLength(23) - estimateWithUriLength(22)).toBe(1);
    expect(estimateWithUriLength(24) - estimateWithUriLength(23)).toBe(2);
    expect(estimateWithUriLength(25) - estimateWithUriLength(24)).toBe(1);
  });

  it('steps to a 3-byte header at 256', () => {
    expect(estimateWithUriLength(255) - estimateWithUriLength(254)).toBe(1);
    expect(estimateWithUriLength(256) - estimateWithUriLength(255)).toBe(2);
    expect(estimateWithUriLength(257) - estimateWithUriLength(256)).toBe(1);
  });
});

describe('estimateRecordBytes — path-1 COSE_Sign1 constant', () => {
  it('matches the real detached path-1 encoding (109 bytes) and stays a bound', () => {
    const record: PoeRecord = { v: 1, items: [{ hashes: { 'sha2-256': digest(0xab) } }] };
    const seed = new Uint8Array(32).fill(0x44);
    const signerPubkey = getPublicKeyEd25519({ seed });
    const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
    const signature = signEd25519({ seed, message: sigStructureBytes });
    const { coseSign1Bytes, sigEntry } = assembleCoseSign1({ record, signerPubkey, signature });

    // The estimator charges exactly the fixed-shape path-1 length.
    expect(coseSign1Bytes.length).toBe(109);

    const signed: PoeRecord = { ...record, sigs: [sigEntry] };
    expectUpperBound({ items: [{ hashAlgs: ['sha2-256'] }], signed: true }, signed);
  });
});

describe('estimateRecordBytes — tightness near the ceiling', () => {
  it('over-charges a sealed X-Wing signed record by at most 64 bytes', () => {
    const recipients = xwingRecipients(3);
    const uri = 'ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEF';
    const hashes = { 'sha2-256': digest(0x09) };
    const shape: RecordShape = {
      items: [
        {
          hashAlgs: ['sha2-256'],
          uris: [uri],
          recipientCount: recipients.length,
          kem: 'mlkem768x25519',
        },
      ],
      signed: true,
    };
    const record = signRecord({
      v: 1,
      items: [{ hashes, uris: [uri], enc: sealedEnvelope(hashes, recipients, 'mlkem768x25519') }],
    });
    const actual = encodePoeRecord(record).length;
    const estimate = estimateRecordBytes(shape);
    expect(estimate).toBeGreaterThanOrEqual(actual);
    // The exact-width estimator's only slack is the fixed margin + the
    // fixed-id maxima (AEAD/KEM ids), together well under 64 bytes.
    expect(estimate - actual).toBeLessThanOrEqual(64);
  });

  it('does not reject a realistic many-X-Wing record whose real CBOR is sub-ceiling', () => {
    // Each X-Wing slot is ~1185 bytes encoded; 11 slots + the base record sit
    // just under 14_000. The real encoding must be sub-ceiling AND the
    // estimate must stay at or under the ceiling, or a valid record would be
    // falsely rejected before a quote is even requested.
    const recipients = xwingRecipients(11);
    const uri = 'ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEF';
    const hashes = { 'sha2-256': digest(0x09) };
    const shape: RecordShape = {
      items: [
        {
          hashAlgs: ['sha2-256'],
          uris: [uri],
          recipientCount: recipients.length,
          kem: 'mlkem768x25519',
        },
      ],
      signed: true,
    };
    const record = signRecord({
      v: 1,
      items: [{ hashes, uris: [uri], enc: sealedEnvelope(hashes, recipients, 'mlkem768x25519') }],
    });
    const actual = encodePoeRecord(record).length;
    expect(actual).toBeLessThan(MAX_RECORD_BYTES);
    expect(actual).toBeGreaterThan(MAX_RECORD_BYTES - 1500);
    const estimate = estimateRecordBytes(shape);
    expect(estimate).toBeGreaterThanOrEqual(actual);
    expect(estimate).toBeLessThanOrEqual(MAX_RECORD_BYTES);
  });
});

describe('estimateRecordBytes — UTF-8 string sizing', () => {
  // CBOR text strings are length-prefixed by their UTF-8 BYTE count. Charging
  // JS code units instead would undercount every non-ASCII character and
  // silently break the upper-bound contract ('é' is 1 code unit, 2 bytes).
  const NON_ASCII_URI = 'é'.repeat(24); // 24 code units, 48 UTF-8 bytes

  it('charges strings by UTF-8 byte length, not code units', () => {
    const nonAscii = estimateRecordBytes({
      items: [{ hashAlgs: ['sha2-256'], uris: [NON_ASCII_URI] }],
    });
    const asciiSameBytes = estimateRecordBytes({
      items: [{ hashAlgs: ['sha2-256'], uris: ['a'.repeat(48)] }],
    });
    expect(nonAscii).toBe(asciiSameBytes);
  });

  it('stays an upper bound for a record carrying a non-ASCII URI-like string', () => {
    const shape: RecordShape = { items: [{ hashAlgs: ['sha2-256'], uris: [NON_ASCII_URI] }] };
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': digest(0xab) }, uris: [NON_ASCII_URI] }],
    };
    expectUpperBound(shape, record);
  });
});

describe('estimateRecordBytes — precision guard on absurd inputs', () => {
  it('never under-estimates on an absurd recipient count (no float rounding below the ceiling)', () => {
    // Past 2^53 the slots product would lose float precision and could round
    // DOWN; the saturating slot arithmetic must pin instead, so an absurd
    // shape can never slip under the ceiling check.
    const estimate = estimateRecordBytes({
      items: [
        {
          hashAlgs: ['sha2-256'],
          recipientCount: Number.MAX_SAFE_INTEGER,
          kem: 'mlkem768x25519',
        },
      ],
    });
    expect(Number.isNaN(estimate)).toBe(false);
    expect(estimate).toBeGreaterThanOrEqual(MAX_RECORD_BYTES);
  });
});
