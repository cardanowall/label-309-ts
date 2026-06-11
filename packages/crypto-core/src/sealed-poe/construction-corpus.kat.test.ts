// Fixture-consumption gates for pinned conformance vectors that the inline
// self-generated tests in this package do not byte-pin:
//
//   1. x25519-kek-salt.json / hybrid-kek-salt.json — the per-slot KEK salts
//      SHA-256(label || enc.nonce || <epk | kem_ct> || pub_R), asserted
//      byte-for-byte after re-deriving pub_R from the recipient secret.
//   2. construction-negative.json — the all-zero X25519 shared-secret slot
//      (treated as failed, never a key match) and the post-seal nonce swap
//      (KEK-salt + transcript binding).
//   3. transcript-bytes.json — the exact canonicalEncode output of
//      SLOTS_TRANSCRIPT and PASSPHRASE_TRANSCRIPT plus the hashes_hash pin.
//      Pinning the byte strings directly localises a canonical-encoding
//      divergence to the encoder rather than surfacing it only as a downstream
//      slots_mac / commitment mismatch.
//
// These read the shared conformance corpus committed under this package's
// tests/fixtures — the same vectors mirrored into the Python and Rust twins —
// so a single byte of divergence in the salt construction or the unwrap
// reason classification fails cross-implementation.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';
import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';
import { x25519PublicKey } from '../kem/x25519';

import {
  CARDANO_POE_PW_NORM_PROFILE,
  CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX,
  computePassphraseHash,
  computeSlotsHash,
  itemHashesHash,
  x25519KekSalt,
  xwingKekSalt,
  type ItemHashes,
} from './transcript';
import { eciesSealedPoeUnwrap, type UnwrapFailureReason } from './unwrap';
import {
  SEALED_POE_AEAD,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as T;
}

// ---------------------------------------------------------------------------
// x25519-kek-salt.json
// ---------------------------------------------------------------------------

interface X25519KekSaltCorpus {
  vector: {
    name: string;
    recipient_secret_hex: string;
    recipient_public_hex: string;
    epk_hex: string;
    enc_nonce_hex: string;
    salt_label_ascii: string;
    expected_kek_salt_hex: string;
  };
}

describe('sealed-poe x25519 KEK salt — pinned conformance vector', () => {
  it('re-derives pub_R from the secret and reproduces the pinned salt byte-for-byte', () => {
    const { vector } = loadFixture<X25519KekSaltCorpus>('x25519-kek-salt.json');
    const pubR = x25519PublicKey({ secretKey: hexToBytes(vector.recipient_secret_hex) });
    expect(bytesToHex(pubR)).toBe(vector.recipient_public_hex);
    expect(vector.salt_label_ascii).toBe('cardano-poe-x25519-kek-salt-v1');

    const salt = x25519KekSalt({
      nonce: hexToBytes(vector.enc_nonce_hex),
      epk: hexToBytes(vector.epk_hex),
      pubR,
    });
    expect(bytesToHex(salt)).toBe(vector.expected_kek_salt_hex);
  });
});

// ---------------------------------------------------------------------------
// hybrid-kek-salt.json
// ---------------------------------------------------------------------------

interface HybridKekSaltCorpus {
  vector: {
    name: string;
    recipient_seed_hex: string;
    recipient_public_hex: string;
    kem_ct_hex: string;
    enc_nonce_hex: string;
    salt_label_ascii: string;
    expected_kek_salt_hex: string;
  };
}

describe('sealed-poe hybrid KEK salt — pinned conformance vector', () => {
  it('re-derives pub_R from the seed and reproduces the pinned salt byte-for-byte', () => {
    const { vector } = loadFixture<HybridKekSaltCorpus>('hybrid-kek-salt.json');
    const seed = hexToBytes(vector.recipient_seed_hex);
    const kemCt = hexToBytes(vector.kem_ct_hex);

    // pub_R is recomputed from the recipient seed via the X-Wing keygen, exactly
    // as the unwrap path does it once per private key. The 1216-byte public key
    // MUST match the recorded value, proving the fixture's secret material is
    // internally consistent.
    const { publicKey } = mlkem768x25519Keygen(seed);
    expect(bytesToHex(publicKey)).toBe(vector.recipient_public_hex);
    expect(kemCt.length).toBe(1120);
    expect(publicKey.length).toBe(1216);

    const salt = xwingKekSalt({
      nonce: hexToBytes(vector.enc_nonce_hex),
      kemCt,
      pubR: publicKey,
    });
    expect(bytesToHex(salt)).toBe(vector.expected_kek_salt_hex);
  });
});

// ---------------------------------------------------------------------------
// construction-negative.json
// ---------------------------------------------------------------------------

interface X25519SlotHex {
  epk_hex: string;
  wrap_hex: string;
}

interface X25519EnvelopeHex {
  scheme: number;
  aead: string;
  kem: string;
  nonce_hex: string;
  slots: X25519SlotHex[];
  slots_mac_hex: string;
}

interface AllZeroSharedVector {
  name: string;
  envelope: X25519EnvelopeHex;
  hashes: Record<string, string>;
  ciphertext_hex: string;
  recipient_secret_hex: string;
  expected_reason: UnwrapFailureReason;
}

interface HybridSlotHex {
  kem_ct_hex: string;
  wrap_hex: string;
}

interface HybridEnvelopeHex {
  scheme: number;
  aead: string;
  kem: string;
  nonce_hex: string;
  slots: HybridSlotHex[];
  slots_mac_hex: string;
}

interface HybridHeaderBindingVector {
  name: string;
  envelope: HybridEnvelopeHex;
  hashes: Record<string, string>;
  ciphertext_hex: string;
  // The recipient's X-Wing secret seed (the hybrid path's recipient secret).
  recipient_secret_hex: string;
  expected_reason: UnwrapFailureReason;
}

interface ConstructionNegativeCorpus {
  all_zero_shared_vectors: AllZeroSharedVector[];
  hybrid_header_binding_vectors: HybridHeaderBindingVector[];
}

function x25519EnvelopeFromHex(env: X25519EnvelopeHex): SealedEnvelope {
  const slots: X25519Slot[] = env.slots.map((s) => ({
    epk: hexToBytes(s.epk_hex),
    wrap: hexToBytes(s.wrap_hex),
  }));
  return {
    scheme: env.scheme as 1,
    aead: env.aead as typeof SEALED_POE_AEAD,
    kem: env.kem as 'x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

function hybridEnvelopeFromHex(env: HybridEnvelopeHex): SealedEnvelope {
  const slots: Mlkem768X25519Slot[] = env.slots.map((s) => ({
    kem_ct: hexToBytes(s.kem_ct_hex),
    wrap: hexToBytes(s.wrap_hex),
  }));
  return {
    scheme: env.scheme as 1,
    aead: env.aead as typeof SEALED_POE_AEAD,
    kem: env.kem as 'mlkem768x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

describe('sealed-poe construction negatives — pinned conformance vectors', () => {
  const corpus = loadFixture<ConstructionNegativeCorpus>('construction-negative.json');

  for (const v of corpus.all_zero_shared_vectors) {
    it(`an all-zero X25519 shared secret is a failed slot, not a key match: ${v.name}`, () => {
      const result = eciesSealedPoeUnwrap({
        envelope: x25519EnvelopeFromHex(v.envelope),
        ciphertext: hexToBytes(v.ciphertext_hex),
        hashes: hashesFromHex(v.hashes),
        recipientSecretKey: hexToBytes(v.recipient_secret_hex),
      });
      expect(result.matched).toBe(false);
      if (!result.matched) {
        expect(result.reason).toBe(v.expected_reason);
      }
    });
  }

  for (const v of corpus.hybrid_header_binding_vectors) {
    it(`a post-seal nonce swap breaks the envelope binding: ${v.name}`, () => {
      // The nonce participates in both the per-slot KEK salt and the slots
      // transcript, so a swapped nonce already fails the wrap-open — the
      // pinned expected_reason captures the observable classification.
      const result = eciesSealedPoeUnwrap({
        envelope: hybridEnvelopeFromHex(v.envelope),
        ciphertext: hexToBytes(v.ciphertext_hex),
        hashes: hashesFromHex(v.hashes),
        recipientSecretKey: hexToBytes(v.recipient_secret_hex),
      });
      expect(result.matched).toBe(false);
      if (!result.matched) {
        expect(result.reason).toBe(v.expected_reason);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// transcript-bytes.json
// ---------------------------------------------------------------------------

// The transcript-bytes corpus carries three vector kinds, discriminated on
// field presence: item-hashes-only pins (just the labelled digest), the
// SLOTS_TRANSCRIPT pins (a `kem` field), and the PASSPHRASE_TRANSCRIPT pin.
interface TranscriptHashesVector {
  name: string;
  hashes: Record<string, string>;
  expected_hashes_hash_hex: string;
}

interface TranscriptSlotVector extends TranscriptHashesVector {
  kem: 'x25519' | 'mlkem768x25519';
  nonce_hex: string;
  expected_slots_transcript_canonical_hex: string;
  expected_slots_hash_hex: string;
}

interface TranscriptPassphraseVector extends TranscriptHashesVector {
  nonce_hex: string;
  salt_hex: string;
  params: { m: number; t: number; p: number };
  expected_passphrase_transcript_canonical_hex: string;
  expected_pw_hash_hex: string;
}

interface TranscriptBytesCorpus {
  vectors: Array<TranscriptHashesVector | TranscriptSlotVector | TranscriptPassphraseVector>;
}

// Reconstruct the SLOTS_TRANSCRIPT canonical bytes the same way computeSlotsHash
// does internally (prefix + sha256 applied separately), so the raw pre-hash
// byte string can be asserted directly against the pinned vector.
function slotsTranscriptBytes(
  kem: 'x25519' | 'mlkem768x25519',
  nonce: Uint8Array,
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  hashesHash: Uint8Array,
): Uint8Array {
  const slotMaps: CanonicalCborValue =
    kem === 'x25519'
      ? (slots as ReadonlyArray<X25519Slot>).map((s) => ({ epk: s.epk, wrap: s.wrap }))
      : (slots as ReadonlyArray<Mlkem768X25519Slot>).map((s) => ({
          kem_ct: s.kem_ct,
          wrap: s.wrap,
        }));
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'slots',
    aead: SEALED_POE_AEAD,
    kem,
    nonce,
    slots: slotMaps,
    hashes_hash: hashesHash,
  };
  return encodeCanonicalCbor(transcript);
}

// Reconstruct the PASSPHRASE_TRANSCRIPT canonical bytes (the closed six-key
// map, `passphrase` itself closed, the normalization profile pinned).
function passphraseTranscriptBytes(v: TranscriptPassphraseVector, hashesHash: Uint8Array) {
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'passphrase',
    aead: SEALED_POE_AEAD,
    nonce: hexToBytes(v.nonce_hex),
    hashes_hash: hashesHash,
    passphrase: {
      alg: 'argon2id',
      salt: hexToBytes(v.salt_hex),
      params: { m: v.params.m, t: v.params.t, p: v.params.p },
      normalization: CARDANO_POE_PW_NORM_PROFILE,
    },
  };
  return encodeCanonicalCbor(transcript);
}

describe('sealed-poe canonical transcript bytes — pinned conformance vectors', () => {
  const corpus = loadFixture<TranscriptBytesCorpus>('transcript-bytes.json');
  const wrapN3 = loadFixture<{ vector: { expected_slots: X25519SlotHex[] } }>('wrap-n3.json');
  const wrapHybridN1 = loadFixture<{
    vector: { expected_slots: Array<{ kem_ct_hex: string; wrap_hex: string }> };
  }>('wrap-hybrid-n1.json');

  for (const v of corpus.vectors) {
    if (!('kem' in v) && !('expected_passphrase_transcript_canonical_hex' in v)) {
      it(`reproduces the labelled item-hashes digest: ${v.name}`, () => {
        const hashesHash = itemHashesHash(hashesFromHex(v.hashes));
        expect(bytesToHex(hashesHash)).toBe(v.expected_hashes_hash_hex);
      });
    } else if ('kem' in v) {
      it(`reproduces hashes_hash + SLOTS_TRANSCRIPT bytes: ${v.name}`, () => {
        const nonce = hexToBytes(v.nonce_hex);
        const hashes = hashesFromHex(v.hashes);
        const hashesHash = itemHashesHash(hashes);
        expect(bytesToHex(hashesHash)).toBe(v.expected_hashes_hash_hex);

        const slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot> =
          v.kem === 'x25519'
            ? wrapN3.vector.expected_slots.map((s) => ({
                epk: hexToBytes(s.epk_hex),
                wrap: hexToBytes(s.wrap_hex),
              }))
            : wrapHybridN1.vector.expected_slots.map((s) => ({
                kem_ct: hexToBytes(s.kem_ct_hex),
                wrap: hexToBytes(s.wrap_hex),
              }));

        // Raw canonical transcript bytes.
        expect(bytesToHex(slotsTranscriptBytes(v.kem, nonce, slots, hashesHash))).toBe(
          v.expected_slots_transcript_canonical_hex,
        );
        // slots_hash = SHA-256(prefix || transcript) via the production helper.
        const slotsHash = computeSlotsHash({
          aead: SEALED_POE_AEAD,
          kem: v.kem,
          nonce,
          slots,
          hashesHash,
        });
        expect(bytesToHex(slotsHash)).toBe(v.expected_slots_hash_hex);

        // The prefix length invariant the helper relies on.
        expect(CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length).toBe(31);
      });
    } else {
      it(`reproduces hashes_hash + PASSPHRASE_TRANSCRIPT bytes: ${v.name}`, () => {
        const hashes = hashesFromHex(v.hashes);
        const hashesHash = itemHashesHash(hashes);
        expect(bytesToHex(hashesHash)).toBe(v.expected_hashes_hash_hex);

        expect(bytesToHex(passphraseTranscriptBytes(v, hashesHash))).toBe(
          v.expected_passphrase_transcript_canonical_hex,
        );
        // pw_hash = SHA-256(prefix || transcript) via the production helper.
        const pwHash = computePassphraseHash({
          aead: SEALED_POE_AEAD,
          nonce: hexToBytes(v.nonce_hex),
          hashesHash,
          salt: hexToBytes(v.salt_hex),
          params: v.params,
        });
        expect(bytesToHex(pwHash)).toBe(v.expected_pw_hash_hex);
      });
    }
  }
});
