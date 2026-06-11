// Verifier-side resource bounds enforced before any KEM/AEAD primitive runs:
// the slot-count cap (MAX_SLOTS) and the decoded-envelope byte backstop
// (MAX_DECODED_ENVELOPE_BYTES). Both bound a public parser's work on a malformed
// envelope; neither is a wire field. Each is pinned as a constant, asserted to
// reject above the bound, and asserted to accept just below — without building a
// giant envelope where a smaller one proves the boundary.

import { describe, expect, it } from 'vitest';

import { EciesSealedPoeError } from './errors';
import { eciesSealedPoeUnwrap } from './unwrap';
import { MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS, type ItemHashes } from './transcript';
import { SEALED_POE_AEAD, type SealedEnvelope, type X25519Slot } from './wrap';

const NONCE_LENGTH = 24;
const SLOTS_MAC_LENGTH = 32;
const EPK_LENGTH = 32;
const WRAP_LENGTH = 48;
const PER_SLOT_X25519 = EPK_LENGTH + WRAP_LENGTH; // 80

// A distinct, well-formed epk per slot (the duplicate-KEM-material gate forbids
// repeats). The bytes need not be valid points — the resource-bound checks run
// before any KEM primitive, so a structurally-shaped envelope suffices.
function distinctSlots(count: number): X25519Slot[] {
  const slots: X25519Slot[] = [];
  for (let i = 0; i < count; i++) {
    const epk = new Uint8Array(EPK_LENGTH);
    epk[0] = i & 0xff;
    epk[1] = (i >> 8) & 0xff;
    slots.push({ epk, wrap: new Uint8Array(WRAP_LENGTH) });
  }
  return slots;
}

const HASHES: ItemHashes = { 'sha2-256': new Uint8Array(32) };

function envelopeWithSlots(slots: X25519Slot[]): SealedEnvelope {
  return {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    kem: 'x25519',
    nonce: new Uint8Array(NONCE_LENGTH),
    slots,
    slots_mac: new Uint8Array(SLOTS_MAC_LENGTH),
  };
}

// Run the unwrap and return the EciesSealedPoeError code it threw, or null if
// it did not throw. The bound errors carry a structured `code`; assert on that
// rather than the human-readable message.
function unwrapErrorCode(slots: X25519Slot[]): string | null {
  try {
    eciesSealedPoeUnwrap({
      envelope: envelopeWithSlots(slots),
      ciphertext: new Uint8Array(16),
      hashes: HASHES,
      recipientSecretKey: new Uint8Array(32).fill(0x11),
    });
    return null;
  } catch (e) {
    if (e instanceof EciesSealedPoeError) return e.code;
    throw e;
  }
}

describe('sealed-poe verifier resource bounds', () => {
  it('pins the bound constants', () => {
    expect(MAX_SLOTS).toBe(1024);
    expect(MAX_DECODED_ENVELOPE_BYTES).toBe(65536);
  });

  it('rejects an envelope with more than MAX_SLOTS slots', () => {
    // MAX_SLOTS + 1 slots trips the slot-count cap. (The decoded-size backstop
    // would also trip here, but the slot-count check runs first.)
    expect(unwrapErrorCode(distinctSlots(MAX_SLOTS + 1))).toBe('ENC_SLOTS_TOO_MANY');
  });

  it('rejects an envelope whose decoded size exceeds the byte backstop', () => {
    // The largest slot count whose decoded size is still over the byte backstop
    // but at or below MAX_SLOTS, so the byte backstop (not the slot cap) is the
    // tripping check. floor((65536 - 56) / 80) = 818 slots fit; 819 exceed it.
    const overByteBound =
      Math.floor((MAX_DECODED_ENVELOPE_BYTES - NONCE_LENGTH - SLOTS_MAC_LENGTH) / PER_SLOT_X25519) +
      1;
    expect(overByteBound).toBeLessThanOrEqual(MAX_SLOTS);
    expect(unwrapErrorCode(distinctSlots(overByteBound))).toBe('ENC_ENVELOPE_TOO_LARGE');
  });

  it('accepts (does not trip a resource bound for) an envelope just below the byte backstop', () => {
    // One slot fewer than the byte-bound trip: the resource checks pass, so the
    // unwrap proceeds to the trial-decrypt loop and returns a structured
    // non-match (the slots are not real wraps) rather than a resource error.
    const justUnder = Math.floor(
      (MAX_DECODED_ENVELOPE_BYTES - NONCE_LENGTH - SLOTS_MAC_LENGTH) / PER_SLOT_X25519,
    );
    const result = eciesSealedPoeUnwrap({
      envelope: envelopeWithSlots(distinctSlots(justUnder)),
      ciphertext: new Uint8Array(16),
      hashes: HASHES,
      recipientSecretKey: new Uint8Array(32).fill(0x11),
    });
    expect(result.matched).toBe(false);
  });
});
