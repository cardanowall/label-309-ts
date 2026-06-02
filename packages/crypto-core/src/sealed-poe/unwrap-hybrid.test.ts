// Behavioural unit tests for the hybrid (mlkem768x25519 / X-Wing) unwrap branch:
// constant-time-N inner-loop coverage, wrong-recipient non-match, and the
// KEM_CT_LENGTH_MISMATCH structural pre-check. The byte-pinned wrap/unwrap
// round-trip lives in wrap-hybrid.kat.test.ts; the slots_mac-covers-kem_ct
// tamper proof lives in unwrap-hybrid-slots-mac.regression.test.ts.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';

import { EciesSealedPoeError } from './errors';
import { chunkKemCt } from './slots-codec';
import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, type Mlkem768X25519Slot, type SealedEnvelope } from './wrap';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] as number).toString(16).padStart(2, '0');
  return s;
}

// Build a deterministic N-recipient hybrid envelope sealed to the given seeds.
function buildHybrid(args: { seeds: Uint8Array[]; cek: number; nonce: number }): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  secretSeeds: Uint8Array[];
  plaintext: Uint8Array;
} {
  const keys = args.seeds.map((s) => mlkem768x25519Keygen(s));
  const plaintext = new TextEncoder().encode('hybrid-unwrap-unit');
  const out = eciesSealedPoeWrap({
    plaintext,
    recipientPublicKeys: keys.map((k) => k.publicKey),
    kem: 'mlkem768x25519',
    cek: fillBytes(args.cek, 32),
    nonce: fillBytes(args.nonce, 24),
    eseeds: args.seeds.map((_, i) => fillBytes(0xe0 + i, 64)),
    skipShuffle: true,
  });
  return {
    envelope: out.envelope,
    ciphertext: out.ciphertext,
    secretSeeds: keys.map((k) => k.secretSeed),
    plaintext,
  };
}

describe('sealed-poe unwrap (hybrid) — constant-time-N inner loop', () => {
  it('enters all N slots regardless of which slot matches (constantTimeN default true)', () => {
    const seeds = [0x11, 0x22, 0x33, 0x44].map((b) => fillBytes(b, 32));
    const built = buildHybrid({ seeds, cek: 0xab, nonce: 0xcd });
    const n = built.envelope.slots.length;
    expect(n).toBe(4);

    // Each recipient maps to a distinct slot index (skipShuffle => slot i is
    // recipient i). For each, the inner loop must still attempt all N slots.
    for (let i = 0; i < n; i++) {
      const slotsAttemptedOut = { count: 0 };
      const res = eciesSealedPoeUnwrap({
        envelope: built.envelope,
        ciphertext: built.ciphertext,
        recipientSecretKey: built.secretSeeds[i]!,
        _slotsAttemptedOut: slotsAttemptedOut,
      });
      expect(res.matched).toBe(true);
      expect(slotsAttemptedOut.count).toBe(n);
    }
  });

  it('short-circuits at matchedSlotIdx+1 when constantTimeN=false', () => {
    const seeds = [0x11, 0x22, 0x33, 0x44].map((b) => fillBytes(b, 32));
    const built = buildHybrid({ seeds, cek: 0xab, nonce: 0xcd });
    // Recipient 0 occupies slot 0, so the loop should stop after 1 iteration.
    const slotsAttemptedOut = { count: 0 };
    const res = eciesSealedPoeUnwrap({
      envelope: built.envelope,
      ciphertext: built.ciphertext,
      recipientSecretKey: built.secretSeeds[0]!,
      constantTimeN: false,
      _slotsAttemptedOut: slotsAttemptedOut,
    });
    expect(res.matched).toBe(true);
    expect(slotsAttemptedOut.count).toBe(1);
  });
});

describe('sealed-poe unwrap (hybrid) — wrong recipient', () => {
  it('returns matched=false WRONG_RECIPIENT_KEY for an unrelated seed', () => {
    const seeds = [0x11, 0x22].map((b) => fillBytes(b, 32));
    const built = buildHybrid({ seeds, cek: 0xa0, nonce: 0xb0 });
    const outsider = mlkem768x25519Keygen(fillBytes(0xfe, 32));
    const res = eciesSealedPoeUnwrap({
      envelope: built.envelope,
      ciphertext: built.ciphertext,
      recipientSecretKey: outsider.secretSeed,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('WRONG_RECIPIENT_KEY');
  });
});

describe('sealed-poe unwrap (hybrid) — structural pre-checks', () => {
  it('raises KEM_CT_LENGTH_MISMATCH when kem_ct does not reassemble to 1120 bytes', () => {
    const seeds = [fillBytes(0x11, 32)];
    const built = buildHybrid({ seeds, cek: 0xa1, nonce: 0xb1 });
    if (built.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');
    const slot0 = built.envelope.slots[0]!;
    // Drop the last chunk so the reassembled enc is short of 1120 bytes.
    const truncated: Mlkem768X25519Slot = {
      kem_ct: slot0.kem_ct.slice(0, slot0.kem_ct.length - 1),
      wrap: slot0.wrap,
    };
    const tampered: SealedEnvelope = {
      ...built.envelope,
      slots: [truncated],
    };
    const recipient = mlkem768x25519Keygen(seeds[0]!);
    expect(() =>
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        recipientSecretKey: recipient.secretSeed,
      }),
    ).toThrow(EciesSealedPoeError);
    try {
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        recipientSecretKey: recipient.secretSeed,
      });
    } catch (e) {
      expect(e).toBeInstanceOf(EciesSealedPoeError);
      if (e instanceof EciesSealedPoeError) expect(e.code).toBe('KEM_CT_LENGTH_MISMATCH');
    }
  });

  it('raises KEM_CT_LENGTH_MISMATCH when kem_ct is over-length (extra chunk)', () => {
    const seeds = [fillBytes(0x12, 32)];
    const built = buildHybrid({ seeds, cek: 0xa2, nonce: 0xb2 });
    if (built.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');
    const slot0 = built.envelope.slots[0]!;
    const overlong: Mlkem768X25519Slot = {
      kem_ct: [...slot0.kem_ct, chunkKemCt(fillBytes(0x00, 8))[0]!],
      wrap: slot0.wrap,
    };
    const tampered: SealedEnvelope = { ...built.envelope, slots: [overlong] };
    const recipient = mlkem768x25519Keygen(seeds[0]!);
    try {
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        recipientSecretKey: recipient.secretSeed,
      });
      throw new Error('expected EciesSealedPoeError');
    } catch (e) {
      expect(e).toBeInstanceOf(EciesSealedPoeError);
      if (e instanceof EciesSealedPoeError) expect(e.code).toBe('KEM_CT_LENGTH_MISMATCH');
    }
  });
});

// Shared cross-SDK chunking-invariance KAT. The honest 1120-byte X-Wing kem_ct
// is re-served with NON-canonical chunk boundaries (e.g. [1, 63, 64*16, 32]).
// Because slots_mac is computed over the kem_ct CANONICALIZED to 64-byte chunks
// (reassemble + re-split before the MAC), an honest recipient still opens the
// re-chunked envelope (matched=true); a byte-flip on an untouched slot still
// breaks the MAC (matched=false, TAMPERED_HEADER). This proves the MAC commits
// to the ciphertext bytes, not the transport chunk boundaries.
interface RechunkedSlot {
  readonly kem_ct_chunks_hex: ReadonlyArray<string>;
  readonly wrap_hex: string;
}
interface RechunkedEnvelope {
  readonly scheme: number;
  readonly aead: string;
  readonly kem: string;
  readonly nonce_hex: string;
  readonly slots: ReadonlyArray<RechunkedSlot>;
  readonly slots_mac_hex: string;
}
interface RechunkedTrueVector {
  readonly name: string;
  readonly envelope: RechunkedEnvelope;
  readonly ciphertext_hex: string;
  readonly recipient_secrets_hex: ReadonlyArray<string>;
  readonly expected: { readonly matched: true; readonly plaintext_hex: string };
}
interface RechunkedFalseVector {
  readonly name: string;
  readonly envelope: RechunkedEnvelope;
  readonly ciphertext_hex: string;
  readonly recipient_secrets_hex: ReadonlyArray<string>;
  readonly expected: { readonly matched: false; readonly reason: string };
}
interface RechunkedCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly matched_true_vectors: ReadonlyArray<RechunkedTrueVector>;
  readonly matched_false_vectors: ReadonlyArray<RechunkedFalseVector>;
}

function envelopeFromFixture(env: RechunkedEnvelope): SealedEnvelope {
  if (env.kem !== 'mlkem768x25519') throw new Error(`unexpected kem ${env.kem}`);
  return {
    scheme: 1,
    aead: 'xchacha20-poly1305',
    kem: 'mlkem768x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots: env.slots.map((s) => ({
      kem_ct: s.kem_ct_chunks_hex.map(hexToBytes),
      wrap: hexToBytes(s.wrap_hex),
    })),
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

const rechunkedCorpus = JSON.parse(
  fs.readFileSync(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../tests/fixtures/sealed-poe/unwrap-hybrid-rechunked.json',
    ),
    'utf8',
  ),
) as RechunkedCorpus;

describe('sealed-poe unwrap (hybrid) — shared cross-SDK kem_ct chunking-invariance KAT', () => {
  for (const vector of rechunkedCorpus.matched_true_vectors) {
    it(`${vector.name} → matched, recovers plaintext`, () => {
      const res = eciesSealedPoeUnwrap({
        envelope: envelopeFromFixture(vector.envelope),
        ciphertext: hexToBytes(vector.ciphertext_hex),
        recipientSecretKey: hexToBytes(vector.recipient_secrets_hex[0]!),
      });
      expect(res.matched).toBe(true);
      if (res.matched) {
        expect(bytesToHex(res.plaintext)).toBe(vector.expected.plaintext_hex);
      }
    });
  }

  for (const vector of rechunkedCorpus.matched_false_vectors) {
    it(`${vector.name} → not matched (${vector.expected.reason})`, () => {
      const res = eciesSealedPoeUnwrap({
        envelope: envelopeFromFixture(vector.envelope),
        ciphertext: hexToBytes(vector.ciphertext_hex),
        recipientSecretKey: hexToBytes(vector.recipient_secrets_hex[0]!),
      });
      expect(res.matched).toBe(false);
      if (!res.matched) {
        expect(res.reason).toBe(vector.expected.reason);
      }
    });
  }
});
