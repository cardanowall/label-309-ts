// Regression: an envelope repeating per-slot KEM material across two slots is
// rejected before any trial-decrypt.
//
// The zero-nonce per-slot wrap is safe only because each slot's KEK is unique
// (each slot draws fresh KEM randomness). Two slots sharing the same epk
// (x25519) or the same reassembled kem_ct (hybrid) derive the same KEK and
// repeat a (KEK, zero-nonce) pair — the exact condition the construction
// forbids. The verifier rejects such an envelope with a typed structural error
// rather than entering the loop, so a KEK-reuse record never decrypts.

import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';
import { x25519PublicKey } from '../kem/x25519';

import { EciesSealedPoeError } from './errors';
import { eciesSealedPoeTrialDecrypt, eciesSealedPoeUnwrap } from './unwrap';
import {
  eciesSealedPoeWrap,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

describe('sealed-poe unwrap — per-slot KEK uniqueness', () => {
  it('rejects a duplicate x25519 epk across slots (ENC_SLOTS_DUPLICATE_KEM_MATERIAL)', () => {
    const recipientPriv = fillBytes(0x20, 32);
    const recipientPub = x25519PublicKey({ secretKey: recipientPriv });
    const out = eciesSealedPoeWrap({
      plaintext: new TextEncoder().encode('kek-reuse-x25519'),
      recipientPublicKeys: [recipientPub, x25519PublicKey({ secretKey: fillBytes(0x40, 32) })],
      skipShuffle: true,
    });
    if (out.envelope.kem !== 'x25519') throw new Error('expected x25519 envelope');
    const slots = out.envelope.slots as ReadonlyArray<X25519Slot>;
    // Force slot 1 to repeat slot 0's epk — the KEK-reuse condition.
    const tampered: SealedEnvelope = {
      ...out.envelope,
      slots: [slots[0]!, { epk: slots[0]!.epk, wrap: slots[1]!.wrap }],
    };
    expect(() =>
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: out.ciphertext,
        recipientSecretKey: recipientPriv,
      }),
    ).toThrowError(expect.objectContaining({ code: 'ENC_SLOTS_DUPLICATE_KEM_MATERIAL' }));
    // The same rejection holds at trial-decrypt time.
    try {
      eciesSealedPoeTrialDecrypt({ envelope: tampered, recipientSecretKeys: [recipientPriv] });
      throw new Error('expected EciesSealedPoeError');
    } catch (e) {
      expect(e).toBeInstanceOf(EciesSealedPoeError);
      expect((e as EciesSealedPoeError).code).toBe('ENC_SLOTS_DUPLICATE_KEM_MATERIAL');
    }
  });

  it('rejects a duplicate hybrid kem_ct across slots (ENC_SLOTS_DUPLICATE_KEM_MATERIAL)', () => {
    const keyA = mlkem768x25519Keygen(fillBytes(0x11, 32));
    const keyB = mlkem768x25519Keygen(fillBytes(0x22, 32));
    const out = eciesSealedPoeWrap({
      plaintext: new TextEncoder().encode('kek-reuse-hybrid'),
      recipientPublicKeys: [keyA.publicKey, keyB.publicKey],
      kem: 'mlkem768x25519',
      eseeds: [fillBytes(0xe1, 64), fillBytes(0xe2, 64)],
      skipShuffle: true,
    });
    if (out.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid envelope');
    const slots = out.envelope.slots as ReadonlyArray<Mlkem768X25519Slot>;
    // Force slot 1 to reuse slot 0's kem_ct chunks — same reassembled ciphertext.
    const tampered: SealedEnvelope = {
      ...out.envelope,
      slots: [slots[0]!, { kem_ct: slots[0]!.kem_ct, wrap: slots[1]!.wrap }],
    };
    expect(() =>
      eciesSealedPoeUnwrap({
        envelope: tampered,
        ciphertext: out.ciphertext,
        recipientSecretKey: keyA.secretSeed,
      }),
    ).toThrowError(expect.objectContaining({ code: 'ENC_SLOTS_DUPLICATE_KEM_MATERIAL' }));
  });

  it('accepts distinct KEM material across slots (honest envelope round-trips)', () => {
    const recipientPriv = fillBytes(0x33, 32);
    const out = eciesSealedPoeWrap({
      plaintext: new TextEncoder().encode('honest-distinct'),
      recipientPublicKeys: [
        x25519PublicKey({ secretKey: recipientPriv }),
        x25519PublicKey({ secretKey: fillBytes(0x44, 32) }),
      ],
      skipShuffle: true,
    });
    const res = eciesSealedPoeUnwrap({
      envelope: out.envelope,
      ciphertext: out.ciphertext,
      recipientSecretKey: recipientPriv,
    });
    expect(res.matched).toBe(true);
  });
});
