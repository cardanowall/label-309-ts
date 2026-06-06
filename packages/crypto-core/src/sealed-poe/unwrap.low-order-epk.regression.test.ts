// Regression: a structurally valid sealed envelope carrying a small-order
// (low-order) Montgomery `epk` in one of its slots must NOT crash trial-decrypt.
//
// Bug: `tryRecipientUnwrapWithIdx` called `x25519Ecdh` OUTSIDE the per-slot
// try/catch. @noble/curves rejects a small-order peer public key (the X25519
// shared secret is all-zero, RFC 7748 §6.1 contributory check) by throwing,
// and because that throw was not an `AeadVerificationError` it escaped
// `eciesSealedPoeUnwrap` / `eciesSealedPoeTrialDecrypt` entirely — an
// attacker-supplied on-chain envelope could turn an inbox scan into an
// uncaught exception. A wrong-LENGTH epk is blocked upstream by
// `assertEnvelopeStructure`, so the low-order point is the only runtime-
// reachable throw inside the loop.
//
// Fix: a low-order epk slot is a non-match (no conformant wrap for this
// recipient could have produced it) and is skipped exactly like an AEAD-tag
// failure. This test pins that contract: the primitive returns a no-match
// result and never throws.

import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import {
  eciesSealedPoeTrialDecrypt,
  eciesSealedPoeUnwrap,
  type TrialDecryptOnlyResult,
  type UnwrapResult,
} from './unwrap';
import { eciesSealedPoeWrap, type SealedEnvelope, type X25519Slot } from './wrap';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Canonical small-order Curve25519 u-coordinates (RFC 7748 §6.1 + the order-8
// points). Every one of these makes the X25519 shared secret all-zero, so a
// conformant KEM rejects them.
const LOW_ORDER_EPKS: ReadonlyArray<{ name: string; epk: Uint8Array }> = [
  {
    name: 'all-zero u (order 1)',
    epk: hexToBytes('0000000000000000000000000000000000000000000000000000000000000000'),
  },
  {
    name: 'u=1 (order 1)',
    epk: hexToBytes('0100000000000000000000000000000000000000000000000000000000000000'),
  },
  {
    name: 'canonical order-8 point',
    epk: hexToBytes('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'),
  },
  {
    name: 'p-1 (order 2)',
    epk: hexToBytes('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
  },
];

function deterministicPriv(seed: number): Uint8Array {
  const priv = new Uint8Array(32);
  for (let j = 0; j < 32; j++) priv[j] = (seed + j) & 0xff;
  return priv;
}

// A distinct low-order point to pair with `epk` so a two-slot envelope carries
// DIFFERENT low-order epks per slot. Per-slot KEK uniqueness forbids two slots
// sharing the same epk, so the regression scenarios use two distinct points;
// both still drive the X25519 shared secret to all-zero, which is the property
// under test.
function otherLowOrderEpk(epk: Uint8Array): Uint8Array {
  const epkHex = bytesToHex(epk);
  const partner = LOW_ORDER_EPKS.find((e) => bytesToHex(e.epk) !== epkHex);
  if (partner === undefined) throw new Error('no distinct low-order epk available');
  return partner.epk;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// A valid two-slot envelope, then replace ONE slot's epk with a low-order
// point. Returns the recipient priv that legitimately matches the OTHER slot.
function buildEnvelopeWithLowOrderSlot(lowOrderEpk: Uint8Array): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  matchingPriv: Uint8Array;
  nonMatchingPriv: Uint8Array;
} {
  const recipientPriv = deterministicPriv(0x20);
  const otherPriv = deterministicPriv(0x60);
  const recipientPublicKeys = [
    x25519PublicKey({ secretKey: recipientPriv }),
    x25519PublicKey({ secretKey: otherPriv }),
  ];
  const plaintext = new TextEncoder().encode('low-order-epk-regression');
  // skipShuffle keeps slot order deterministic so we know which slot to clobber.
  const out = eciesSealedPoeWrap({ plaintext, recipientPublicKeys, skipShuffle: true });
  if (out.envelope.kem !== 'x25519') throw new Error('expected x25519 envelope');

  // Clobber the SECOND slot's epk with the low-order point. The first slot is
  // still a legitimate wrap for `recipientPriv`. Note this also invalidates the
  // slots_mac, so an unwrap that gets a CEK from slot 0 will report
  // TAMPERED_HEADER — but crucially it must NOT throw. (Slot 0 keeps its honest
  // epk, so the two slots' epks differ and per-slot KEK uniqueness holds.)
  const slots: X25519Slot[] = out.envelope.slots.map((s, i) =>
    i === 1 ? { epk: lowOrderEpk, wrap: s.wrap } : s,
  );
  const envelope: SealedEnvelope = { ...out.envelope, slots };
  return {
    envelope,
    ciphertext: out.ciphertext,
    matchingPriv: recipientPriv,
    nonMatchingPriv: deterministicPriv(0xa0),
  };
}

// An envelope where EVERY slot is a low-order point — no slot can ECDH-open, so
// the only correct behaviour is a clean no-match.
function buildAllLowOrderEnvelope(lowOrderEpk: Uint8Array): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
} {
  const recipientPublicKeys = [
    x25519PublicKey({ secretKey: deterministicPriv(0x11) }),
    x25519PublicKey({ secretKey: deterministicPriv(0x55) }),
  ];
  const out = eciesSealedPoeWrap({
    plaintext: new TextEncoder().encode('all-low-order'),
    recipientPublicKeys,
    skipShuffle: true,
  });
  if (out.envelope.kem !== 'x25519') throw new Error('expected x25519 envelope');
  // Every slot carries a low-order epk, but the two slots use DISTINCT low-order
  // points so per-slot KEK uniqueness holds — the property under test is that an
  // all-zero shared secret per slot is a non-match, not a duplicate-epk reject.
  const partnerEpk = otherLowOrderEpk(lowOrderEpk);
  const slots: X25519Slot[] = out.envelope.slots.map((s, i) => ({
    epk: i === 0 ? lowOrderEpk : partnerEpk,
    wrap: s.wrap,
  }));
  return { envelope: { ...out.envelope, slots }, ciphertext: out.ciphertext };
}

describe('sealed-poe unwrap — low-order epk slot is a non-match, never a throw', () => {
  for (const { name, epk } of LOW_ORDER_EPKS) {
    describe(`epk = ${name}`, () => {
      it('eciesSealedPoeUnwrap (single-priv, non-matching priv) returns matched=false', () => {
        const { envelope, ciphertext } = buildAllLowOrderEnvelope(epk);
        let result: UnwrapResult | undefined;
        expect(() => {
          result = eciesSealedPoeUnwrap({
            envelope,
            ciphertext,
            recipientSecretKey: deterministicPriv(0x99),
          });
        }).not.toThrow();
        expect(result?.matched).toBe(false);
      });

      it('eciesSealedPoeUnwrap (multi-priv) returns matched=false with all low-order slots', () => {
        const { envelope, ciphertext } = buildAllLowOrderEnvelope(epk);
        let result: UnwrapResult | undefined;
        expect(() => {
          result = eciesSealedPoeUnwrap({
            envelope,
            ciphertext,
            recipientSecretKeys: [deterministicPriv(0x99), deterministicPriv(0xcd)],
          });
        }).not.toThrow();
        expect(result?.matched).toBe(false);
      });

      it('eciesSealedPoeTrialDecrypt does not throw and reports no_aead_pass', () => {
        const { envelope } = buildAllLowOrderEnvelope(epk);
        let result: TrialDecryptOnlyResult | undefined;
        expect(() => {
          result = eciesSealedPoeTrialDecrypt({
            envelope,
            recipientSecretKeys: [deterministicPriv(0x99)],
          });
        }).not.toThrow();
        expect(result?.kind).toBe('no_aead_pass');
      });

      it('a legitimate slot still opens even when a sibling slot has a low-order epk', () => {
        // Slot 0 is a real wrap for matchingPriv; slot 1 carries the low-order
        // epk. The ECDH on slot 1 would have thrown pre-fix; now it is skipped.
        // The recovered CEK opens slot 0, but slots_mac no longer matches the
        // clobbered slot set, so the verdict is TAMPERED_HEADER — the point is
        // that we get a structured verdict instead of an exception.
        const { envelope, ciphertext, matchingPriv } = buildEnvelopeWithLowOrderSlot(epk);
        let result: UnwrapResult | undefined;
        expect(() => {
          result = eciesSealedPoeUnwrap({
            envelope,
            ciphertext,
            recipientSecretKey: matchingPriv,
          });
        }).not.toThrow();
        expect(result?.matched).toBe(false);
        if (result && !result.matched) {
          expect(result.reason).toBe('TAMPERED_HEADER');
        }
      });

      it('constant-time-N still enters every slot when a low-order epk follows the match', () => {
        // With constantTimeN=true (default) the loop must enter all slots even
        // after recovering a CEK, and a low-order epk in a trailing slot must
        // not turn that into a throw.
        const { envelope, ciphertext, matchingPriv } = buildEnvelopeWithLowOrderSlot(epk);
        const slotsAttemptedOut = { count: 0 };
        expect(() => {
          eciesSealedPoeUnwrap({
            envelope,
            ciphertext,
            recipientSecretKey: matchingPriv,
            _slotsAttemptedOut: slotsAttemptedOut,
          });
        }).not.toThrow();
        expect(slotsAttemptedOut.count).toBe(envelope.slots.length);
      });
    });
  }
});
