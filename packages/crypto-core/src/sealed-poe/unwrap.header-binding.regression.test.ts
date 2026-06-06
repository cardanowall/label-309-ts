// Regression: the slot-set MAC binds the cross-KEM header fields, not just the
// slot bytes.
//
// The slots transcript carries `scheme`, `path`, `aead`, `kem`, and `nonce`
// alongside the canonicalised slots, so a relay that flips a header field while
// leaving the slot shapes valid produces a different `slots_hash` and the MAC
// fails. This pins the `nonce` case: the per-slot wrap is nonce-independent (it
// uses a zero nonce keyed by the KEK), so a candidate CEK is still recovered
// from the honest slot — but the recomputed `slots_hash` over the tampered nonce
// no longer matches the on-wire `slots_mac`, so the verdict is TAMPERED_HEADER
// (the CEK is recovered, the content AEAD is never reached).

import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, type SealedEnvelope } from './wrap';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

describe('sealed-poe unwrap — header binding via the slots transcript', () => {
  it('flipping the envelope nonce yields TAMPERED_HEADER (CEK recovered, MAC fails)', () => {
    const recipientPriv = fillBytes(0x20, 32);
    const out = eciesSealedPoeWrap({
      plaintext: new TextEncoder().encode('header-binding-nonce'),
      recipientPublicKeys: [x25519PublicKey({ secretKey: recipientPriv })],
      nonce: fillBytes(0xcd, 24),
      skipShuffle: true,
    });

    // Sanity: the honest envelope opens cleanly.
    const clean = eciesSealedPoeUnwrap({
      envelope: out.envelope,
      ciphertext: out.ciphertext,
      recipientSecretKey: recipientPriv,
    });
    expect(clean.matched).toBe(true);

    // Flip the nonce only. The per-slot wrap is unaffected (zero-nonce, KEK-
    // keyed), so the CEK is still recovered — but the transcript binds the nonce,
    // so slots_hash differs and the MAC check fails.
    const tampered: SealedEnvelope = { ...out.envelope, nonce: fillBytes(0xce, 24) };
    const res = eciesSealedPoeUnwrap({
      envelope: tampered,
      ciphertext: out.ciphertext,
      recipientSecretKey: recipientPriv,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) {
      expect(res.reason).toBe('TAMPERED_HEADER');
    }
  });
});
