// Pins the prepared-seal cross-SDK parity vectors
// (tests/fixtures/prepared-seal/): the exact `prepared_seal_json_v1`
// serialization, the fingerprint, the per-item derivations, and the record
// bytes a deterministic `sealPrepare` run produces. The Rust and Python SDKs
// assert byte-identical values from mirrored copies of the same fixtures, so
// the portable artifact cannot drift between implementations.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { sha256 } from '@cardanowall/crypto-core/hash';
import {
  deriveMlKem768X25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
} from '@cardanowall/crypto-core/seed-derive';

import { bytesToHex } from '../hex';
import {
  encodeSealedRecord,
  preparedSealFromJson,
  preparedSealToJson,
  sealPrepareWithRng,
  type DeterministicRng,
} from './sealed';

interface PreparedSealVector {
  readonly description: string;
  readonly deterministic_rng: { readonly type: string; readonly start: number };
  readonly kem: 'x25519' | 'mlkem768x25519';
  readonly hash_alg: string;
  readonly recipient_seeds_hex: readonly string[];
  readonly recipient_public_keys_hex: readonly string[];
  readonly plaintexts_hex: readonly string[];
  readonly uris: readonly string[];
  readonly supersedes: null;
  readonly signers: null;
  readonly expected: {
    readonly prepared_seal_json: string;
    readonly prepared_sha256: string;
    readonly item_ids: readonly string[];
    readonly upload_idempotency_keys: readonly string[];
    readonly record_hex: string;
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/prepared-seal');

function loadVector(name: string): PreparedSealVector {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, name), 'utf8')) as PreparedSealVector;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * The counter byte source the fixtures declare: byte `n` of the stream is
 * `(start + n) mod 256`.
 */
function counterRng(start: number): DeterministicRng {
  let state = start;
  return (out: Uint8Array) => {
    for (let i = 0; i < out.length; i++) {
      out[i] = state & 0xff;
      state = (state + 1) % 256;
    }
  };
}

async function runVector(name: string): Promise<void> {
  const vector = loadVector(name);
  expect(vector.deterministic_rng.type).toBe('counter-u8');
  expect(vector.hash_alg).toBe('sha2-256');

  // Recipient keys derive from the pinned seeds — both are in the fixture so
  // a twin without the derivation helpers can use the keys directly.
  const recipients = vector.recipient_seeds_hex.map((seedHex) => {
    const seed = hexToBytes(seedHex);
    return vector.kem === 'x25519'
      ? deriveX25519KeypairFromSeed(seed).publicKey
      : deriveMlKem768X25519KeypairFromSeed(seed).publicKey;
  });
  expect(recipients.map((key) => bytesToHex(key))).toEqual(vector.recipient_public_keys_hex);

  const prepared = sealPrepareWithRng(
    {
      items: vector.plaintexts_hex.map((hex) => ({ content: hexToBytes(hex) })),
      recipients,
      kem: vector.kem,
    },
    counterRng(vector.deterministic_rng.start),
  );

  // The portable serialization must match byte-for-byte.
  expect(preparedSealToJson(prepared)).toBe(vector.expected.prepared_seal_json);
  expect(prepared.preparedSha256).toBe(vector.expected.prepared_sha256);
  expect(prepared.items.map((item) => item.itemId)).toEqual([...vector.expected.item_ids]);
  expect(prepared.items.map((_, index) => prepared.uploadIdempotencyKey(index))).toEqual([
    ...vector.expected.upload_idempotency_keys,
  ]);

  // The record bytes for the pinned uris, unsigned, no supersedes.
  expect(vector.supersedes).toBeNull();
  expect(vector.signers).toBeNull();
  const record = await encodeSealedRecord(prepared, vector.uris);
  expect(bytesToHex(record)).toBe(vector.expected.record_hex);

  // The pinned serialization also round-trips through the parser with its
  // fingerprint verified — and re-serializes to the identical string.
  const parsed = preparedSealFromJson(vector.expected.prepared_seal_json);
  expect(preparedSealToJson(parsed)).toBe(vector.expected.prepared_seal_json);
  expect(bytesToHex(await encodeSealedRecord(parsed, vector.uris))).toBe(
    vector.expected.record_hex,
  );
}

describe('prepared-seal cross-SDK parity vectors', () => {
  it('pins the single-item hybrid vector', async () => {
    await runVector('single-item-mlkem768x25519.json');
  });

  it('pins the multi-item classical vector', async () => {
    await runVector('multi-item-x25519.json');
  });

  // The only vector that drives the n >= 3 slot shuffle (rejection-sampled
  // draws) together with per-slot X-Wing eseeds; a shuffle or eseed divergence
  // surfaces as a serialization mismatch against the Rust-authored canonical.
  it('pins the multi-item hybrid shuffle vector', async () => {
    await runVector('multi-item-hybrid.json');
  });

  it('item ids are the SHA-256 of each ciphertext', () => {
    const vector = loadVector('multi-item-x25519.json');
    const parsed = preparedSealFromJson(vector.expected.prepared_seal_json);
    for (const item of parsed.items) {
      expect(item.itemId).toBe(bytesToHex(sha256(item.ciphertext())));
    }
  });
});
