// Regression: header tampering is caught — at the KEK layer for fields bound
// into the per-slot KEK salt, and at the slot-set MAC for everything the
// transcript commits to.
//
// The envelope nonce is bound TWICE: into every per-slot KEK salt and into the
// slots transcript. Flipping it therefore fails the wrap-open itself (the
// recipient derives a different KEK), surfacing as the non-recipient outcome —
// tampering is indistinguishable from not-addressed, which is the stronger
// posture. Transcript-only material (slot order, the item's hash claim,
// slots_mac itself) still wrap-opens, so those flips surface as the
// tampered-header diagnostic: a CEK was recovered but nothing passed the folded
// per-slot acceptance.

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, type SealedEnvelope } from './wrap';
import type { ItemHashes } from './transcript';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

const PLAINTEXT = new TextEncoder().encode('header-binding');
const HASHES: ItemHashes = { 'sha2-256': sha256(PLAINTEXT) };

function sealTwoSlots(): { out: ReturnType<typeof eciesSealedPoeWrap>; priv: Uint8Array } {
  const priv = fillBytes(0x20, 32);
  const out = eciesSealedPoeWrap({
    plaintext: PLAINTEXT,
    hashes: HASHES,
    recipientPublicKeys: [
      x25519PublicKey({ secretKey: priv }),
      x25519PublicKey({ secretKey: fillBytes(0x40, 32) }),
    ],
    nonce: fillBytes(0xcd, 24),
    skipShuffle: true,
  });
  // Sanity: the honest envelope opens cleanly.
  const clean = eciesSealedPoeUnwrap({
    envelope: out.envelope,
    ciphertext: out.ciphertext,
    hashes: HASHES,
    recipientSecretKey: priv,
  });
  expect(clean.matched).toBe(true);
  return { out, priv };
}

describe('sealed-poe unwrap — header binding', () => {
  it('flipping the envelope nonce fails at the KEK layer (nonce is in every KEK salt)', () => {
    const { out, priv } = sealTwoSlots();
    const tampered: SealedEnvelope = { ...out.envelope, nonce: fillBytes(0xce, 24) };
    const res = eciesSealedPoeUnwrap({
      envelope: tampered,
      ciphertext: out.ciphertext,
      hashes: HASHES,
      recipientSecretKey: priv,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) {
      // No slot wrap-opens under the flipped nonce, so the outcome is the
      // non-recipient one — indistinguishable from not being addressed.
      expect(res.reason).toBe('WRONG_RECIPIENT_KEY');
    }
  });

  it('reordering slots yields TAMPERED_HEADER (CEK recovered, transcript order broken)', () => {
    const { out, priv } = sealTwoSlots();
    if (out.envelope.kem !== 'x25519') throw new Error('expected x25519');
    const reordered: SealedEnvelope = {
      ...out.envelope,
      slots: [out.envelope.slots[1]!, out.envelope.slots[0]!],
    };
    const res = eciesSealedPoeUnwrap({
      envelope: reordered,
      ciphertext: out.ciphertext,
      hashes: HASHES,
      recipientSecretKey: priv,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('TAMPERED_HEADER');
  });

  it('splicing the envelope onto a different hash claim yields TAMPERED_HEADER', () => {
    const { out, priv } = sealTwoSlots();
    const res = eciesSealedPoeUnwrap({
      envelope: out.envelope,
      ciphertext: out.ciphertext,
      hashes: { 'sha2-256': sha256(new Uint8Array([0x01])) },
      recipientSecretKey: priv,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('TAMPERED_HEADER');
  });

  it('flipping a slots_mac byte yields TAMPERED_HEADER', () => {
    const { out, priv } = sealTwoSlots();
    const flipped = Uint8Array.from(out.envelope.slots_mac);
    flipped[0]! ^= 0xff;
    const res = eciesSealedPoeUnwrap({
      envelope: { ...out.envelope, slots_mac: flipped },
      ciphertext: out.ciphertext,
      hashes: HASHES,
      recipientSecretKey: priv,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('TAMPERED_HEADER');
  });
});
