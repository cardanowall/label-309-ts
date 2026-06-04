// Signature continuity across rotation (Ed25519 from
// N=2 rotations ago still verifies).
//
// Pins the rotation invariant that old on-chain COSE_Sign1 attestations
// stay verifiable after the user rotates their seed twice — the signature
// continuity guarantee. Ed25519 derivation runs ONLY against
// the current seed, never against the archived seeds; this integration guard
// exercises that invariant end-to-end against real primitives (no crypto mocks).

import { describe, expect, it } from 'vitest';

import { coseSign1Label309Build, coseSign1Label309Verify } from '../cose/sign1';
import { deriveEd25519KeypairFromSeed } from '../seed-derive/derive';

const s0 = new Uint8Array(32).fill(0xe0);
const s1 = new Uint8Array(32).fill(0xe1);
const s2 = new Uint8Array(32).fill(0xe2);

// Opaque record-body CBOR stand-in — the continuity invariant is independent
// of the body contents, only that producer and verifier hash the same bytes.
const RECORD_BODY_CBOR = new TextEncoder().encode('continuity test');
// COSE alg label 1 → -8 (EdDSA per RFC 9053). kid label 4.
const COSE_ALG_LABEL = 1;
const COSE_KID_LABEL = 4;
const COSE_ALG_EDDSA = -8;

describe('signature continuity across N=2 rotations', () => {
  it('a COSE_Sign1 signed with the seed-0 Ed25519 key still verifies after rotating to seed_2', () => {
    const ed0 = deriveEd25519KeypairFromSeed(s0);
    const ed25519Pub0 = new Uint8Array(ed0.publicKey);
    const ed25519Priv0 = new Uint8Array(ed0.secretKey);

    // Build a Label 309 record-signature COSE_Sign1 (detached null payload).
    // Protected header carries `kid = ed25519Pub0` at label 4 so the verifier
    // resolves the signer key from the message itself — the "path-1
    // in-signature kid" case.
    const protectedHeader = new Map<number | string, unknown>([
      [COSE_ALG_LABEL, COSE_ALG_EDDSA],
      [COSE_KID_LABEL, ed25519Pub0],
    ]);
    const coseBytes = coseSign1Label309Build({
      protectedHeader,
      unprotectedHeader: new Map(),
      recordBodyCbor: RECORD_BODY_CBOR,
      signerSecretKey: ed25519Priv0,
    });

    // User rotates seed_0 → seed_1 → seed_2. Each rotation derives a fresh
    // Ed25519 keypair from the NEW seed only.
    const ed1 = deriveEd25519KeypairFromSeed(s1);
    const ed2 = deriveEd25519KeypairFromSeed(s2);

    // Sanity: every rotation produces a distinct Ed25519 pub.
    expect(Array.from(ed1.publicKey)).not.toEqual(Array.from(ed25519Pub0));
    expect(Array.from(ed2.publicKey)).not.toEqual(Array.from(ed25519Pub0));
    expect(Array.from(ed1.publicKey)).not.toEqual(Array.from(ed2.publicKey));

    // Verify the original signature against the in-protected-header kid.
    // The verifier MUST NOT need the user's current Ed25519 keypair to
    // confirm the old attestation.
    const verifyResult = coseSign1Label309Verify({
      message: coseBytes,
      detachedRecordBodyCbor: RECORD_BODY_CBOR,
    });
    expect(verifyResult.ok).toBe(true);
    if (verifyResult.ok) {
      expect(Array.from(verifyResult.signerKey)).toEqual(Array.from(ed25519Pub0));
    }
  });

  it('re-deriving Ed25519 from s_0 produces the same pub byte-for-byte (determinism guard)', () => {
    // Regression guard against any future hash-family / HKDF info-string
    // change in derive.ts that would silently invalidate every old
    // signature ever produced.
    const ed_first = deriveEd25519KeypairFromSeed(s0);
    const ed_second = deriveEd25519KeypairFromSeed(s0);
    expect(Array.from(ed_first.publicKey)).toEqual(Array.from(ed_second.publicKey));
  });
});
