import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { xchacha20Poly1305Encrypt } from '../aead/xchacha20-poly1305';
import { hkdfSha256 } from '../kdf/hkdf';
import { x25519PublicKey } from '../kem/x25519';

import { adContentSlots, computeSlotsHash, slotsPayloadKey } from './transcript';
import { eciesSealedPoeTrialDecrypt, eciesSealedPoeUnwrap } from './unwrap';
import {
  CARDANO_POE_HKDF_INFO_SLOTS_MAC,
  eciesSealedPoeWrap,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Build an envelope spliced from two single-slot wraps that address the SAME
// recipient but carry DIFFERENT CEKs, then re-key the slots_mac and content
// ciphertext to the FIRST slot's CEK. With this construction:
//   - the per-slot epk of each slot differs (no duplicate-KEM-material gate),
//   - slot 0 recovers cek_a; slot 0's CEK passes the (re-keyed) slots_mac,
//   - slot 1 recovers a DIFFERENT cek_b.
// A verifier that selected only the first match and skipped the rest would
// accept this (it is exactly the gap the CEK-conflict check closes). The
// conflict check rejects it because a later matching slot recovered a different
// CEK.
function buildCekConflictEnvelope(): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  recipientSecretKey: Uint8Array;
} {
  const recipientSecretKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) recipientSecretKey[i] = (0xd0 + i) & 0xff;
  const pub = x25519PublicKey({ secretKey: recipientSecretKey });

  const cekA = new Uint8Array(32).fill(0xaa);
  const cekB = new Uint8Array(32).fill(0xbb);
  const nonce = new Uint8Array(24);
  for (let i = 0; i < 24; i++) nonce[i] = (0xe0 + i) & 0xff;

  const ephA = new Uint8Array(32).fill(0x01);
  const ephB = new Uint8Array(32).fill(0x02);

  const outA = eciesSealedPoeWrap({
    plaintext: new Uint8Array([0x78]),
    recipientPublicKeys: [pub],
    cek: cekA,
    nonce,
    ephemeralSecrets: [ephA],
    skipShuffle: true,
  });
  const outB = eciesSealedPoeWrap({
    plaintext: new Uint8Array([0x78]),
    recipientPublicKeys: [pub],
    cek: cekB,
    nonce,
    ephemeralSecrets: [ephB],
    skipShuffle: true,
  });

  // Both wraps used kem='x25519', so each slot is an X25519Slot.
  const slots: X25519Slot[] = [
    outA.envelope.slots[0] as X25519Slot,
    outB.envelope.slots[0] as X25519Slot,
  ];

  // Re-key the slots_mac and content ciphertext to cek_a over the SPLICED
  // 2-slot transcript, so the first matching slot's CEK passes the MAC and the
  // content opens — isolating the conflict check as the sole rejection cause.
  const slotsHash = computeSlotsHash({ kem: 'x25519', nonce, slots });
  const hmacKey = hkdfSha256({
    ikm: cekA,
    salt: new Uint8Array(0),
    info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
    length: 32,
  });
  const slotsMac = hmac(sha256, hmacKey, slotsHash);

  const payloadKey = slotsPayloadKey({ cek: cekA, nonce });
  const aad = adContentSlots({ kem: 'x25519', nonce, slotsHash, slotsMac });
  const ciphertext = xchacha20Poly1305Encrypt({
    key: payloadKey,
    nonce,
    aad,
    plaintext: new TextEncoder().encode('conflict-probe-plaintext'),
  });

  const envelope: SealedEnvelope = {
    scheme: 1,
    aead: 'xchacha20-poly1305',
    kem: 'x25519',
    nonce,
    slots,
    slots_mac: slotsMac,
  };
  return { envelope, ciphertext, recipientSecretKey };
}

describe('sealed-poe unwrap — CEK conflict defence', () => {
  it('rejects an envelope whose two matching slots recover different CEKs', () => {
    const { envelope, ciphertext, recipientSecretKey } = buildCekConflictEnvelope();
    // Sanity: the two slots carry distinct KEM material, so the duplicate gate
    // does not pre-empt the conflict path.
    const s0 = envelope.slots[0] as X25519Slot;
    const s1 = envelope.slots[1] as X25519Slot;
    expect(Buffer.from(s0.epk)).not.toEqual(Buffer.from(s1.epk));

    const result = eciesSealedPoeUnwrap({ envelope, ciphertext, recipientSecretKey });
    expect(result.matched).toBe(false);
    if (!result.matched) {
      // Generic tampered-header rejection (the conflict is an anomalous slot
      // set, not a key mismatch).
      expect(result.reason).toBe('TAMPERED_HEADER');
    }
  });

  it('rejects via the multi-priv path as well (conflict on the matching priv)', () => {
    const { envelope, ciphertext, recipientSecretKey } = buildCekConflictEnvelope();
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      recipientSecretKeys: [recipientSecretKey],
    });
    expect(result.matched).toBe(false);
    if (!result.matched) expect(result.reason).toBe('TAMPERED_HEADER');
  });

  it('surfaces a conflict as aead_pass_no_mac_match in trial-decrypt', () => {
    const { envelope, recipientSecretKey } = buildCekConflictEnvelope();
    const result = eciesSealedPoeTrialDecrypt({
      envelope,
      recipientSecretKeys: [recipientSecretKey],
    });
    // A conflict is never a clean match; it is the generic "a CEK opened but the
    // slot set is not trusted" outcome.
    expect(result.kind).toBe('aead_pass_no_mac_match');
  });
});

// Positive companion: the same recipient legitimately addressed in two slots
// with fresh distinct ephemerals carrying the SAME CEK MUST still decrypt — the
// conflict check rejects only DIFFERENT recovered CEKs, never honest recipient
// padding.
interface DuplicateRecipientCorpus {
  vector: {
    recipient_secrets_hex: string[];
    envelope: {
      scheme: number;
      aead: string;
      kem: string;
      nonce_hex: string;
      slots: { epk_hex: string; wrap_hex: string }[];
      slots_mac_hex: string;
    };
    ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

describe('sealed-poe unwrap — duplicate recipient (positive)', () => {
  it('decrypts an envelope addressing one recipient in two slots with the same CEK', () => {
    const corpus = JSON.parse(
      fs.readFileSync(path.join(fixturesDir, 'unwrap-duplicate-recipient.json'), 'utf8'),
    ) as DuplicateRecipientCorpus;
    const { vector } = corpus;
    const slots: X25519Slot[] = vector.envelope.slots.map((s) => ({
      epk: hexToBytes(s.epk_hex),
      wrap: hexToBytes(s.wrap_hex),
    }));
    const envelope: SealedEnvelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce: hexToBytes(vector.envelope.nonce_hex),
      slots,
      slots_mac: hexToBytes(vector.envelope.slots_mac_hex),
    };
    const ciphertext = hexToBytes(vector.ciphertext_hex);
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      recipientSecretKey: hexToBytes(vector.recipient_secrets_hex[0]!),
    });
    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(Buffer.from(result.plaintext).toString('hex')).toBe(vector.expected_plaintext_hex);
    }
  });
});
