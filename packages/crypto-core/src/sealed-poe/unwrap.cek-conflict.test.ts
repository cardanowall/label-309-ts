// CEK selection across multiple matching slots.
//
// Per-slot acceptance is `kem_ok AND open_ok AND mac_ok`, so a slot that
// wrap-opens with a CEK that does not reproduce `slots_mac` is inert — a forged
// shadow slot is skipped and an honest slot anywhere in the array still wins
// (the shadow-slot POSITIVE below). The remaining anomaly is two ACCEPTED slots
// recovering different CEKs: that requires a collision in the CEK-keyed
// commitment, so no envelope buildable through the public API can reach the
// branch — the accumulator that implements it is exercised directly instead
// (the spec pins this case as an implementation-level behavioural test).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import {
  finishSlotAcceptance,
  foldSlotAcceptance,
  newSlotAcceptanceState,
} from './slot-acceptance';
import { streamSeal } from './stream';
import { computeSlotsHash, computeSlotsMac, itemHashesHash, slotsPayloadKey } from './transcript';
import { eciesSealedPoeTrialDecrypt, eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, SEALED_POE_AEAD, type SealedEnvelope, type X25519Slot } from './wrap';
import type { ItemHashes } from './transcript';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

const PLAINTEXT = new TextEncoder().encode('shadow-slot-probe-plaintext');
const HASHES: ItemHashes = { 'sha2-256': sha256(PLAINTEXT) };

// Build an envelope spliced from two single-slot wraps that address the SAME
// recipient but carry DIFFERENT CEKs, then re-key slots_mac and the content
// stream to the HONEST slot's CEK over the spliced two-slot transcript. The
// other slot wrap-opens under the recipient's key with a CEK that does NOT
// reproduce slots_mac — exactly the forged-shadow-slot scenario.
function buildShadowSlotEnvelope(honestFirst: boolean): {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  recipientSecretKey: Uint8Array;
  honestSlotIdx: number;
} {
  const recipientSecretKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) recipientSecretKey[i] = (0xd0 + i) & 0xff;
  const pub = x25519PublicKey({ secretKey: recipientSecretKey });

  const honestCek = new Uint8Array(32).fill(0xaa);
  const shadowCek = new Uint8Array(32).fill(0xbb);
  const nonce = new Uint8Array(24);
  for (let i = 0; i < 24; i++) nonce[i] = (0xe0 + i) & 0xff;

  const outHonest = eciesSealedPoeWrap({
    plaintext: new Uint8Array([0x78]),
    hashes: HASHES,
    recipientPublicKeys: [pub],
    cek: honestCek,
    nonce,
    ephemeralSecrets: [new Uint8Array(32).fill(0x01)],
    skipShuffle: true,
  });
  const outShadow = eciesSealedPoeWrap({
    plaintext: new Uint8Array([0x78]),
    hashes: HASHES,
    recipientPublicKeys: [pub],
    cek: shadowCek,
    nonce,
    ephemeralSecrets: [new Uint8Array(32).fill(0x02)],
    skipShuffle: true,
  });

  const honestSlot = outHonest.envelope.slots[0] as X25519Slot;
  const shadowSlot = outShadow.envelope.slots[0] as X25519Slot;
  const slots: X25519Slot[] = honestFirst ? [honestSlot, shadowSlot] : [shadowSlot, honestSlot];
  const honestSlotIdx = honestFirst ? 0 : 1;

  // Re-key slots_mac and the content stream to the honest CEK over the SPLICED
  // 2-slot transcript, so the honest slot passes the folded acceptance while
  // the shadow slot wrap-opens but fails the MAC.
  const slotsHash = computeSlotsHash({
    aead: SEALED_POE_AEAD,
    kem: 'x25519',
    nonce,
    slots,
    hashesHash: itemHashesHash(HASHES),
  });
  const slotsMac = computeSlotsMac({ cek: honestCek, slotsHash });
  const ciphertext = streamSeal({
    payloadKey: slotsPayloadKey({ cek: honestCek, nonce }),
    plaintext: PLAINTEXT,
  });

  const envelope: SealedEnvelope = {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    kem: 'x25519',
    nonce,
    slots,
    slots_mac: slotsMac,
  };
  return { envelope, ciphertext, recipientSecretKey, honestSlotIdx };
}

describe('sealed-poe unwrap — forged shadow slot is inert (per-slot MAC fold)', () => {
  it('decrypts under the honest CEK when the shadow slot precedes the honest slot', () => {
    const { envelope, ciphertext, recipientSecretKey, honestSlotIdx } =
      buildShadowSlotEnvelope(false);
    expect(honestSlotIdx).toBe(1);

    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: HASHES,
      recipientSecretKey,
    });
    expect(result.matched).toBe(true);
    if (result.matched) expect(result.plaintext).toEqual(PLAINTEXT);

    // Trial-decrypt selects the honest slot's index, not the shadow's.
    const trial = eciesSealedPoeTrialDecrypt({
      envelope,
      hashes: HASHES,
      recipientSecretKeys: [recipientSecretKey],
    });
    expect(trial.kind).toBe('match');
    if (trial.kind === 'match') expect(trial.slotIdx).toBe(honestSlotIdx);
  });

  it('decrypts when the honest slot precedes the shadow slot (first accepted slot wins)', () => {
    const { envelope, ciphertext, recipientSecretKey, honestSlotIdx } =
      buildShadowSlotEnvelope(true);
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: HASHES,
      recipientSecretKey,
    });
    expect(result.matched).toBe(true);

    const trial = eciesSealedPoeTrialDecrypt({
      envelope,
      hashes: HASHES,
      recipientSecretKeys: [recipientSecretKey],
    });
    expect(trial.kind).toBe('match');
    if (trial.kind === 'match') expect(trial.slotIdx).toBe(honestSlotIdx);
  });
});

describe('sealed-poe per-slot acceptance accumulator — CEK conflict fails closed', () => {
  const cekA = new Uint8Array(32).fill(0xaa);
  const cekB = new Uint8Array(32).fill(0xbb);

  it('two accepted slots with different CEKs raise cekConflict', () => {
    const state = newSlotAcceptanceState();
    foldSlotAcceptance(state, 1, cekA, 0);
    foldSlotAcceptance(state, 1, cekB, 1);
    const outcome = finishSlotAcceptance(state);
    expect(outcome.found).toBe(true);
    expect(outcome.cekConflict).toBe(true);
  });

  it('two accepted slots with the SAME CEK select the first and raise no conflict', () => {
    const state = newSlotAcceptanceState();
    foldSlotAcceptance(state, 1, cekA, 0);
    foldSlotAcceptance(state, 1, Uint8Array.from(cekA), 3);
    const outcome = finishSlotAcceptance(state);
    expect(outcome.found).toBe(true);
    expect(outcome.cekConflict).toBe(false);
    expect(outcome.selectedSlotIdx).toBe(0);
    expect(outcome.selectedCek).toEqual(cekA);
  });

  it('a rejected slot neither selects a CEK nor raises a conflict', () => {
    const state = newSlotAcceptanceState();
    foldSlotAcceptance(state, 0, cekB, 0); // wrap-opened, MAC failed → not ok
    foldSlotAcceptance(state, 1, cekA, 1);
    foldSlotAcceptance(state, 0, cekB, 2);
    const outcome = finishSlotAcceptance(state);
    expect(outcome.found).toBe(true);
    expect(outcome.cekConflict).toBe(false);
    expect(outcome.selectedSlotIdx).toBe(1);
    expect(outcome.selectedCek).toEqual(cekA);
  });

  it('no accepted slot leaves the state unmatched', () => {
    const state = newSlotAcceptanceState();
    foldSlotAcceptance(state, 0, cekA, 0);
    const outcome = finishSlotAcceptance(state);
    expect(outcome.found).toBe(false);
    expect(outcome.selectedCek).toBeNull();
    expect(outcome.selectedSlotIdx).toBe(-1);
  });

  it('a rejected slot carrying the selected CEK bytes does not disturb the selection', () => {
    // The selection update is a mask fold on every slot — a non-accepted slot
    // (mask 0) must leave the selected CEK, index, found, and conflict state
    // bit-identical even when its candidate equals or differs from the
    // selection.
    const state = newSlotAcceptanceState();
    foldSlotAcceptance(state, 1, cekA, 2);
    foldSlotAcceptance(state, 0, Uint8Array.from(cekA), 5);
    foldSlotAcceptance(state, 0, cekB, 6);
    const outcome = finishSlotAcceptance(state);
    expect(outcome.found).toBe(true);
    expect(outcome.cekConflict).toBe(false);
    expect(outcome.selectedSlotIdx).toBe(2);
    expect(outcome.selectedCek).toEqual(cekA);
  });
});

// Positive companion: the same recipient legitimately addressed in two slots
// with fresh distinct ephemerals carrying the SAME CEK MUST still decrypt — the
// conflict scan rejects only DIFFERENT recovered CEKs, never honest recipient
// padding.
interface DuplicateRecipientCorpus {
  vector: {
    recipient_secrets_hex: string[];
    hashes: Record<string, string>;
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

describe('sealed-poe unwrap — duplicate recipient (positive, pinned vector)', () => {
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
      aead: SEALED_POE_AEAD,
      kem: 'x25519',
      nonce: hexToBytes(vector.envelope.nonce_hex),
      slots,
      slots_mac: hexToBytes(vector.envelope.slots_mac_hex),
    };
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext: hexToBytes(vector.ciphertext_hex),
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKey: hexToBytes(vector.recipient_secrets_hex[0]!),
    });
    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(Buffer.from(result.plaintext).toString('hex')).toBe(vector.expected_plaintext_hex);
    }
  });
});
