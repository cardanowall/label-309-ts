// Fixture-consumption gates for three pinned conformance vectors that the
// inline self-generated tests in this package do not byte-pin:
//
//   1. hybrid-kek-salt.json    — the X-Wing per-slot KEK salt is
//      SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R). Re-derive
//      pub_R from the recipient seed, confirm it matches the recorded public
//      key, then assert the salt byte-for-byte against the pinned vector.
//   2. construction-negative.json — drive the recipient unwrap with an all-zero
//      X25519 shared-secret slot (the recipient must treat the slot as failed,
//      not as a key match) and with a hybrid envelope whose nonce was swapped
//      after sealing (the slots_mac no longer commits to the header, so the
//      candidate CEK is recovered but rejected as a tampered header).
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

import { canonicalizeSlots, chunkKemCt } from './slots-codec';
import {
  adContentPassphrase,
  adContentSlots,
  CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX,
  computeSlotsHash,
  xwingKekSalt,
} from './transcript';
import { eciesSealedPoeUnwrap, type UnwrapFailureReason } from './unwrap';
import { type Mlkem768X25519Slot, type SealedEnvelope, type X25519Slot } from './wrap';

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

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as T;
}

// ---------------------------------------------------------------------------
// hybrid-kek-salt.json
// ---------------------------------------------------------------------------

interface HybridKekSaltCorpus {
  vector: {
    name: string;
    recipient_seed_hex: string;
    recipient_public_hex: string;
    kem_ct_hex: string;
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

    const salt = xwingKekSalt({ kemCt, pubR: publicKey });
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
  ciphertext_hex: string;
  recipient_secret_hex: string;
  expected_reason: UnwrapFailureReason;
}

interface HybridSlotHex {
  kem_ct_chunks_hex: string[];
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
  ciphertext_hex: string;
  recipient_seed_hex: string;
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
    aead: env.aead as 'xchacha20-poly1305',
    kem: env.kem as 'x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

function hybridEnvelopeFromHex(env: HybridEnvelopeHex): SealedEnvelope {
  // The on-wire kem_ct chunks reassemble to the 1120-byte enc; re-chunk
  // canonically so the slot carries the same byte content the transcript
  // commits to (the unwrap path is chunking-invariant by design).
  const slots: Mlkem768X25519Slot[] = env.slots.map((s) => {
    const joined = new Uint8Array(s.kem_ct_chunks_hex.reduce((n, h) => n + h.length / 2, 0));
    let offset = 0;
    for (const h of s.kem_ct_chunks_hex) {
      const chunk = hexToBytes(h);
      joined.set(chunk, offset);
      offset += chunk.length;
    }
    return { kem_ct: chunkKemCt(joined), wrap: hexToBytes(s.wrap_hex) };
  });
  return {
    scheme: env.scheme as 1,
    aead: env.aead as 'xchacha20-poly1305',
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
        recipientSecretKey: hexToBytes(v.recipient_secret_hex),
      });
      expect(result.matched).toBe(false);
      if (!result.matched) {
        expect(result.reason).toBe(v.expected_reason);
      }
    });
  }

  for (const v of corpus.hybrid_header_binding_vectors) {
    it(`a post-seal nonce swap breaks the slots_mac header binding: ${v.name}`, () => {
      // The recipient seed re-derives the same X-Wing key that wrapped a slot,
      // so the candidate CEK is recovered — but the swapped nonce changes the
      // slots transcript, so the CEK-keyed slots_mac no longer matches and the
      // envelope is rejected as a tampered header rather than decrypted.
      const result = eciesSealedPoeUnwrap({
        envelope: hybridEnvelopeFromHex(v.envelope),
        ciphertext: hexToBytes(v.ciphertext_hex),
        recipientSecretKey: hexToBytes(v.recipient_seed_hex),
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
// The exact canonicalEncode output of SLOTS_TRANSCRIPT, AD_CONTENT_SLOTS, and
// AD_CONTENT_PASSPHRASE. Pinning the byte strings directly localises a
// canonical-encoding divergence to the encoder rather than surfacing it only as
// a downstream slots_mac / AEAD-tag mismatch.

interface TranscriptSlotVector {
  name: string;
  kem: 'x25519' | 'mlkem768x25519';
  nonce_hex: string;
  expected_slots_transcript_canonical_hex: string;
  expected_slots_hash_hex: string;
  expected_ad_content_slots_canonical_hex: string;
}

interface TranscriptPassphraseVector {
  name: string;
  nonce_hex: string;
  salt_hex: string;
  params: { m: number; t: number; p: number };
  expected_ad_content_passphrase_canonical_hex: string;
}

interface TranscriptBytesCorpus {
  vectors: Array<TranscriptSlotVector | TranscriptPassphraseVector>;
}

// Reconstruct the SLOTS_TRANSCRIPT canonical bytes the same way computeSlotsHash
// does internally (prefix + sha256 applied separately), so the raw pre-hash
// byte string can be asserted directly against the pinned vector.
function slotsTranscriptBytes(
  kem: 'x25519' | 'mlkem768x25519',
  nonce: Uint8Array,
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
): Uint8Array {
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'slots',
    aead: 'xchacha20-poly1305',
    kem,
    nonce,
    slots: canonicalizeSlots(slots, kem),
  };
  return encodeCanonicalCbor(transcript);
}

describe('sealed-poe canonical transcript / AAD bytes — pinned conformance vectors', () => {
  const corpus = loadFixture<TranscriptBytesCorpus>('transcript-bytes.json');
  const wrapN3 = loadFixture<{ vector: { expected_slots: X25519SlotHex[]; nonce_hex: string } }>(
    'wrap-n3.json',
  );
  const wrapHybridN1 = loadFixture<{
    vector: { expected_slots: Array<{ kem_ct_hex: string; wrap_hex: string }>; nonce_hex: string };
  }>('wrap-hybrid-n1.json');

  for (const v of corpus.vectors) {
    if ('kem' in v) {
      it(`reproduces SLOTS_TRANSCRIPT + AD_CONTENT_SLOTS bytes: ${v.name}`, () => {
        const nonce = hexToBytes(v.nonce_hex);
        const slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot> =
          v.kem === 'x25519'
            ? wrapN3.vector.expected_slots.map((s) => ({
                epk: hexToBytes(s.epk_hex),
                wrap: hexToBytes(s.wrap_hex),
              }))
            : wrapHybridN1.vector.expected_slots.map((s) => ({
                kem_ct: chunkKemCt(hexToBytes(s.kem_ct_hex)),
                wrap: hexToBytes(s.wrap_hex),
              }));

        // Raw canonical transcript bytes.
        expect(bytesToHex(slotsTranscriptBytes(v.kem, nonce, slots))).toBe(
          v.expected_slots_transcript_canonical_hex,
        );
        // slots_hash = SHA-256(prefix || transcript) via the production helper.
        const slotsHash = computeSlotsHash({ kem: v.kem, nonce, slots });
        expect(bytesToHex(slotsHash)).toBe(v.expected_slots_hash_hex);
        // AD_CONTENT_SLOTS binds slots_hash + the slots_mac the wrap fixture
        // pins; assert its full canonical bytes.
        const wrapSlotsMac =
          v.kem === 'x25519'
            ? loadFixture<{ vector: { expected_slots_mac_hex: string } }>('wrap-n3.json').vector
                .expected_slots_mac_hex
            : loadFixture<{ vector: { expected_slots_mac_hex: string } }>('wrap-hybrid-n1.json')
                .vector.expected_slots_mac_hex;
        const ad = adContentSlots({
          kem: v.kem,
          nonce,
          slotsHash,
          slotsMac: hexToBytes(wrapSlotsMac),
        });
        expect(bytesToHex(ad)).toBe(v.expected_ad_content_slots_canonical_hex);

        // The prefix length invariant the helper relies on.
        expect(CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length).toBe(31);
      });
    } else {
      it(`reproduces AD_CONTENT_PASSPHRASE bytes: ${v.name}`, () => {
        const ad = adContentPassphrase({
          nonce: hexToBytes(v.nonce_hex),
          passphrase: {
            alg: 'argon2id',
            salt: hexToBytes(v.salt_hex),
            params: v.params,
          },
        });
        expect(bytesToHex(ad)).toBe(v.expected_ad_content_passphrase_canonical_hex);
      });
    }
  }
});
