// Behavioural unit tests for the hybrid (mlkem768x25519 / X-Wing) unwrap branch:
// constant-across-slots inner-loop coverage, wrong-recipient non-match, the
// garbage-kem_ct behavioural negative, and the KEM_CT_LENGTH_MISMATCH
// structural pre-check. The byte-pinned wrap/unwrap round-trip lives in
// wrap-hybrid.kat.test.ts; the slots_mac-covers-kem_ct tamper proof lives in
// unwrap-hybrid-slots-mac.regression.test.ts.

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';

import { EciesSealedPoeError } from './errors';
import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, type Mlkem768X25519Slot, type SealedEnvelope } from './wrap';
import type { ItemHashes } from './transcript';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

// Build a deterministic N-recipient hybrid envelope sealed to the given seeds.
function buildHybrid(args: { seeds: Uint8Array[]; cek: number; nonce: number }): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  hashes: ItemHashes;
  secretSeeds: Uint8Array[];
  plaintext: Uint8Array;
} {
  const keys = args.seeds.map((s) => mlkem768x25519Keygen(s));
  const plaintext = new TextEncoder().encode('hybrid-unwrap-unit');
  const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
  const out = eciesSealedPoeWrap({
    plaintext,
    hashes,
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
    hashes,
    secretSeeds: keys.map((k) => k.secretSeed),
    plaintext,
  };
}

describe('sealed-poe unwrap (hybrid) — constant-across-slots inner loop', () => {
  it('enters all N slots regardless of which slot matches', () => {
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
        hashes: built.hashes,
        recipientSecretKey: built.secretSeeds[i]!,
        _slotsAttemptedOut: slotsAttemptedOut,
      });
      expect(res.matched).toBe(true);
      expect(slotsAttemptedOut.count).toBe(n);
    }
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
      hashes: built.hashes,
      recipientSecretKey: outsider.secretSeed,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('WRONG_RECIPIENT_KEY');
  });

  it('treats a garbage kem_ct of valid length as not-mine (no distinct decapsulation error)', () => {
    // A 1120-byte kem_ct of arbitrary bytes passes the structural length check;
    // ML-KEM decapsulation implicitly rejects into a pseudorandom shared
    // secret, the wrap-open fails, and the envelope ends in the generic
    // non-recipient outcome — never a thrown KEM error.
    const seeds = [fillBytes(0x11, 32)];
    const built = buildHybrid({ seeds, cek: 0xa3, nonce: 0xb3 });
    if (built.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');
    const garbage = new Uint8Array(1120);
    for (let i = 0; i < garbage.length; i++) garbage[i] = (i * 31 + 7) & 0xff;
    const tampered: SealedEnvelope = {
      ...built.envelope,
      slots: [{ kem_ct: garbage, wrap: built.envelope.slots[0]!.wrap }],
    };
    let res: ReturnType<typeof eciesSealedPoeUnwrap> | undefined;
    expect(() => {
      res = eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        hashes: built.hashes,
        recipientSecretKey: built.secretSeeds[0]!,
      });
    }).not.toThrow();
    expect(res?.matched).toBe(false);
    if (res && !res.matched) expect(res.reason).toBe('WRONG_RECIPIENT_KEY');
  });
});

describe('sealed-poe unwrap (hybrid) — structural pre-checks', () => {
  it('raises KEM_CT_LENGTH_MISMATCH when kem_ct is short of 1120 bytes', () => {
    const seeds = [fillBytes(0x11, 32)];
    const built = buildHybrid({ seeds, cek: 0xa1, nonce: 0xb1 });
    if (built.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');
    const slot0 = built.envelope.slots[0]!;
    const truncated: Mlkem768X25519Slot = {
      kem_ct: slot0.kem_ct.subarray(0, slot0.kem_ct.length - 1),
      wrap: slot0.wrap,
    };
    const tampered: SealedEnvelope = { ...built.envelope, slots: [truncated] };
    const recipient = mlkem768x25519Keygen(seeds[0]!);
    try {
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        hashes: built.hashes,
        recipientSecretKey: recipient.secretSeed,
      });
      throw new Error('expected EciesSealedPoeError');
    } catch (e) {
      expect(e).toBeInstanceOf(EciesSealedPoeError);
      if (e instanceof EciesSealedPoeError) expect(e.code).toBe('KEM_CT_LENGTH_MISMATCH');
    }
  });

  it('raises KEM_CT_LENGTH_MISMATCH when kem_ct is over-length', () => {
    const seeds = [fillBytes(0x12, 32)];
    const built = buildHybrid({ seeds, cek: 0xa2, nonce: 0xb2 });
    if (built.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');
    const slot0 = built.envelope.slots[0]!;
    const overlong = new Uint8Array(slot0.kem_ct.length + 8);
    overlong.set(slot0.kem_ct, 0);
    const tampered: SealedEnvelope = {
      ...built.envelope,
      slots: [{ kem_ct: overlong, wrap: slot0.wrap }],
    };
    const recipient = mlkem768x25519Keygen(seeds[0]!);
    try {
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: built.ciphertext,
        hashes: built.hashes,
        recipientSecretKey: recipient.secretSeed,
      });
      throw new Error('expected EciesSealedPoeError');
    } catch (e) {
      expect(e).toBeInstanceOf(EciesSealedPoeError);
      if (e instanceof EciesSealedPoeError) expect(e.code).toBe('KEM_CT_LENGTH_MISMATCH');
    }
  });
});
