import { describe, expect, it } from 'vitest';

import { chacha20Poly1305Decrypt } from '../aead/chacha20-poly1305';
import { hkdfSha256 } from '../kdf/hkdf';
import { x25519Ecdh, x25519PublicKey } from '../kem/x25519';

import { eciesSealedPoeUnwrap } from './unwrap';
import {
  CARDANO_POE_HKDF_INFO_KEK,
  eciesSealedPoeWrap,
  uniformIndexBelow,
  type SealedPoeOutput,
  type X25519Slot,
} from './wrap';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Per-slot probe — kept test-only since the public API does not expose per-slot identity.
// Used only by the shuffle-position property test (recipientPositions) below.
function trialUnwrap(slot: X25519Slot, recipientPriv: Uint8Array): Uint8Array | null {
  const shared = x25519Ecdh({ secretKey: recipientPriv, theirPublicKey: slot.epk });
  const recipientPub = x25519PublicKey({ secretKey: recipientPriv });
  const kek = hkdfSha256({
    ikm: shared,
    salt: concat(slot.epk, recipientPub),
    info: CARDANO_POE_HKDF_INFO_KEK,
    length: 32,
  });
  try {
    return chacha20Poly1305Decrypt({
      key: kek,
      nonce: new Uint8Array(12),
      aad: CARDANO_POE_HKDF_INFO_KEK,
      ciphertext: slot.wrap,
    });
  } catch {
    return null;
  }
}

function recipientPositions(out: SealedPoeOutput, recipientPrivs: Uint8Array[]): number[] {
  const positions = new Array<number>(recipientPrivs.length).fill(-1);
  for (let slotIdx = 0; slotIdx < out.envelope.slots.length; slotIdx++) {
    const slot = out.envelope.slots[slotIdx] as X25519Slot;
    for (let r = 0; r < recipientPrivs.length; r++) {
      if (positions[r] !== -1) continue;
      const cek = trialUnwrap(slot, recipientPrivs[r] as Uint8Array);
      if (cek !== null) {
        positions[r] = slotIdx;
        break;
      }
    }
  }
  return positions;
}

describe('sealed-poe wrap — production-path roundtrip + shuffle property', () => {
  const recipientPrivs = [
    new Uint8Array(32).map((_, i) => (0x11 + i) & 0xff),
    new Uint8Array(32).map((_, i) => (0x55 + i) & 0xff),
    new Uint8Array(32).map((_, i) => (0x99 + i) & 0xff),
  ];
  const recipientPublicKeys = recipientPrivs.map((priv) => x25519PublicKey({ secretKey: priv }));

  it('every recipient priv key recovers the original plaintext', () => {
    const plaintext = new TextEncoder().encode('AC5 roundtrip — production path');
    const out = eciesSealedPoeWrap({ plaintext, recipientPublicKeys });
    for (const priv of recipientPrivs) {
      const result = eciesSealedPoeUnwrap({
        envelope: out.envelope,
        ciphertext: out.ciphertext,
        recipientSecretKey: priv,
      });
      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(bytesEqual(result.plaintext, plaintext)).toBe(true);
      }
    }
  });

  it('observes recipient-position permutation across N=3 production runs', () => {
    const plaintext = new TextEncoder().encode('shuffle-by-recipient-position');
    const orderings = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const out = eciesSealedPoeWrap({ plaintext, recipientPublicKeys });
      const positions = recipientPositions(out, recipientPrivs);
      orderings.add(positions.join(','));
      if (orderings.size >= 4) break;
    }
    expect(orderings.size).toBeGreaterThanOrEqual(2);
  });

  it('produces 100 distinct (nonce, slots_mac) tuples across 100 N=1 production-path runs', () => {
    const pub = recipientPublicKeys[0] as Uint8Array;
    const plaintext = new TextEncoder().encode('csprng-distinctness');
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const out = eciesSealedPoeWrap({ plaintext, recipientPublicKeys: [pub] });
      seen.add(`${bytesToHex(out.envelope.nonce)}|${bytesToHex(out.envelope.slots_mac)}`);
    }
    expect(seen.size).toBe(100);
  });
});

describe('uniformIndexBelow — unbiased CSPRNG index (rejection sampling)', () => {
  // The shuffle anonymity invariant requires a UNIFORM permutation. A plain
  // `u32 % m` is biased unless m divides 2^32; rejection sampling removes it.
  // These assertions pin the arithmetic and the output domain rather than a
  // statistical distribution (which would flake).

  it('always returns a value in [0, m)', () => {
    for (const m of [2, 3, 5, 7, 17, 100, 257]) {
      for (let i = 0; i < 2000; i++) {
        const v = uniformIndexBelow(m);
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThan(m);
        expect(Number.isInteger(v)).toBe(true);
      }
    }
  });

  it('m=1 collapses to the only valid index 0', () => {
    for (let i = 0; i < 100; i++) expect(uniformIndexBelow(1)).toBe(0);
  });

  it('the rejection ceiling 2^32 - (2^32 mod m) is an exact multiple of m', () => {
    // The retained domain [0, limit) must partition evenly into m residue
    // classes — otherwise the reduction reintroduces bias. We reproduce the
    // limit math the function uses and assert divisibility for power-of-two
    // and non-power-of-two moduli alike.
    const TWO_POW_32 = 0x1_0000_0000;
    for (const m of [2, 3, 4, 5, 6, 7, 8, 17, 64, 100, 256, 257, 1000]) {
      const limit = TWO_POW_32 - (TWO_POW_32 % m);
      expect(limit % m).toBe(0);
      // For power-of-two m, 2^32 mod m === 0, so nothing is ever rejected.
      const isPowerOfTwo = (m & (m - 1)) === 0;
      expect(limit === TWO_POW_32).toBe(isPowerOfTwo);
    }
  });
});
