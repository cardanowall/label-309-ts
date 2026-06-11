// Regression: slots_mac MUST authenticate the hybrid kem_ct.
//
// The #1 correctness risk of the hybrid branch is leaving the ML-KEM ciphertext
// (kem_ct) outside the slot-set MAC. If slots_mac did not cover kem_ct, an
// attacker could swap a recipient's X-Wing ciphertext for one of their own
// while the record's content ciphertext (and the CEK that a DIFFERENT,
// untouched slot recovers) stayed valid — a silent header forgery.
//
// Proof: build a two-slot hybrid envelope. Recipient A opens slot 0 cleanly, so
// a candidate CEK is always recovered. Flip one byte of slot 1's kem_ct.
// Because slots_mac was computed over the ORIGINAL slot-set transcript
// (including slot 1's kem_ct), the recomputed MAC no longer matches → unwrap
// returns matched=false reason=TAMPERED_HEADER. It must be TAMPERED_HEADER, not
// TAMPERED_CIPHERTEXT (the content stream is never reached) and not
// WRONG_RECIPIENT_KEY (the CEK IS recovered from the clean slot 0).

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';

import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, type Mlkem768X25519Slot, type SealedEnvelope } from './wrap';
import type { ItemHashes } from './transcript';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

describe('sealed-poe unwrap (hybrid) — slots_mac covers kem_ct', () => {
  it('flipping a byte of an untouched slot kem_ct yields TAMPERED_HEADER (not TAMPERED_CIPHERTEXT)', () => {
    const keyA = mlkem768x25519Keygen(fillBytes(0x11, 32));
    const keyB = mlkem768x25519Keygen(fillBytes(0x22, 32));

    const plaintext = new TextEncoder().encode('hybrid-slots-mac-kem-ct-coverage');
    const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
    const out = eciesSealedPoeWrap({
      plaintext,
      hashes,
      recipientPublicKeys: [keyA.publicKey, keyB.publicKey],
      kem: 'mlkem768x25519',
      cek: fillBytes(0xab, 32),
      nonce: fillBytes(0xcd, 24),
      eseeds: [fillBytes(0xe1, 64), fillBytes(0xe2, 64)],
      skipShuffle: true,
    });
    if (out.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid');

    // Sanity: recipient A opens cleanly before tampering.
    const clean = eciesSealedPoeUnwrap({
      envelope: out.envelope,
      ciphertext: out.ciphertext,
      hashes,
      recipientSecretKey: keyA.secretSeed,
    });
    expect(clean.matched).toBe(true);

    // Flip one byte of slot 1's kem_ct. Slot 0 (recipient A's) is untouched, so
    // the CEK is still recovered — but the MAC over the slot set now disagrees.
    const slots = out.envelope.slots as ReadonlyArray<Mlkem768X25519Slot>;
    const slot1 = slots[1]!;
    const tamperedKemCt = Uint8Array.from(slot1.kem_ct);
    tamperedKemCt[0] = (tamperedKemCt[0]! ^ 0x01) & 0xff;
    const tamperedEnvelope: SealedEnvelope = {
      ...out.envelope,
      slots: [slots[0]!, { kem_ct: tamperedKemCt, wrap: slot1.wrap }],
    };

    const res = eciesSealedPoeUnwrap({
      envelope: tamperedEnvelope,
      ciphertext: out.ciphertext,
      hashes,
      recipientSecretKey: keyA.secretSeed,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) {
      expect(res.reason).toBe('TAMPERED_HEADER');
    }
  });
});
