// Behavioural tests for the RecipientKeyBundle dispatch added to
// eciesSealedPoeUnwrap / eciesSealedPoeTrialDecrypt. The bundle carries BOTH a
// classical X25519 private-key chain and the X-Wing secret-seed chain; the
// dispatch picks the right list from `envelope.kem`. These prove:
//   • a classical envelope unwraps from bundle.x25519PrivateKeys and ignores
//     the hybrid seed list (and vice-versa for a hybrid envelope);
//   • the bundle result is byte-identical to passing the matching flat list;
//   • an empty selected list is a clean non-match, never a throw, and never
//     invokes a KEM primitive on the other list.

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';
import { x25519PublicKey } from '../kem/x25519';

import { eciesSealedPoeTrialDecrypt, eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap } from './wrap';
import type { ItemHashes } from './transcript';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

const PLAINTEXT = new TextEncoder().encode('bundle-dispatch-roundtrip');
const HASHES: ItemHashes = { 'sha2-256': sha256(PLAINTEXT) };

describe('RecipientKeyBundle dispatch — classical envelope', () => {
  const recipientPriv = fillBytes(0x21, 32);
  const recipientPub = x25519PublicKey({ secretKey: recipientPriv });
  const sealed = eciesSealedPoeWrap({
    plaintext: PLAINTEXT,
    hashes: HASHES,
    recipientPublicKeys: [recipientPub],
    cek: fillBytes(0x33, 32),
    nonce: fillBytes(0x44, 24),
    ephemeralSecrets: [fillBytes(0x55, 32)],
    skipShuffle: true,
  });

  it('unwraps from bundle.x25519PrivateKeys; hybrid seeds are irrelevant', () => {
    const res = eciesSealedPoeUnwrap({
      envelope: sealed.envelope,
      ciphertext: sealed.ciphertext,
      hashes: HASHES,
      recipientKeyBundle: {
        x25519PrivateKeys: [recipientPriv],
        // A non-matching hybrid seed must not interfere — the dispatch never
        // touches it for a classical envelope.
        mlkem768x25519SecretSeeds: [fillBytes(0xfe, 32)],
      },
    });
    expect(res.matched).toBe(true);
    if (res.matched) expect(res.plaintext).toEqual(PLAINTEXT);
  });

  it('bundle trial-decrypt matches the flat-list trial-decrypt byte-for-byte', () => {
    const flat = eciesSealedPoeTrialDecrypt({
      envelope: sealed.envelope,
      hashes: HASHES,
      recipientSecretKeys: [recipientPriv],
    });
    const bundled = eciesSealedPoeTrialDecrypt({
      envelope: sealed.envelope,
      hashes: HASHES,
      recipientKeyBundle: {
        x25519PrivateKeys: [recipientPriv],
        mlkem768x25519SecretSeeds: [],
      },
    });
    expect(bundled.kind).toBe('match');
    expect(flat.kind).toBe('match');
    if (bundled.kind === 'match' && flat.kind === 'match') {
      expect(bundled.slotIdx).toBe(flat.slotIdx);
      expect(bundled.cek).toEqual(flat.cek);
    }
  });

  it('empty x25519 list (archived-only identity) → clean non-match, not a throw', () => {
    const res = eciesSealedPoeUnwrap({
      envelope: sealed.envelope,
      ciphertext: sealed.ciphertext,
      hashes: HASHES,
      recipientKeyBundle: {
        x25519PrivateKeys: [],
        mlkem768x25519SecretSeeds: [fillBytes(0x01, 32)],
      },
    });
    expect(res.matched).toBe(false);
    if (!res.matched) expect(res.reason).toBe('WRONG_RECIPIENT_KEY');

    const trial = eciesSealedPoeTrialDecrypt({
      envelope: sealed.envelope,
      hashes: HASHES,
      recipientKeyBundle: { x25519PrivateKeys: [], mlkem768x25519SecretSeeds: [] },
    });
    expect(trial.kind).toBe('no_match');
  });
});

describe('RecipientKeyBundle dispatch — hybrid envelope', () => {
  const seed = fillBytes(0x11, 32);
  const recipient = mlkem768x25519Keygen(seed);
  const sealed = eciesSealedPoeWrap({
    plaintext: PLAINTEXT,
    hashes: HASHES,
    recipientPublicKeys: [recipient.publicKey],
    kem: 'mlkem768x25519',
    cek: fillBytes(0xab, 32),
    nonce: fillBytes(0xcd, 24),
    eseeds: [fillBytes(0xe0, 64)],
    skipShuffle: true,
  });

  it('unwraps from bundle.mlkem768x25519SecretSeeds; classical privs are irrelevant', () => {
    const res = eciesSealedPoeUnwrap({
      envelope: sealed.envelope,
      ciphertext: sealed.ciphertext,
      hashes: HASHES,
      recipientKeyBundle: {
        x25519PrivateKeys: [fillBytes(0x99, 32)],
        mlkem768x25519SecretSeeds: [recipient.secretSeed],
      },
    });
    expect(res.matched).toBe(true);
    if (res.matched) expect(res.plaintext).toEqual(PLAINTEXT);
  });

  it('empty hybrid seed list (archived-only identity facing hybrid record) → clean non-match', () => {
    const res = eciesSealedPoeTrialDecrypt({
      envelope: sealed.envelope,
      hashes: HASHES,
      recipientKeyBundle: {
        // Holds only classical privs — cannot read a hybrid record.
        x25519PrivateKeys: [fillBytes(0x21, 32)],
        mlkem768x25519SecretSeeds: [],
      },
    });
    expect(res.kind).toBe('no_match');
  });
});
