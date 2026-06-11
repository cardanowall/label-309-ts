// Cross-service interop parity: records published by an independent producer
// implementation must validate and trial-decrypt to byte-identical results
// here.
//
// The fixtures under `../fixtures/cross-service/` are sealed Label 309
// records constructed by the Python SDK's standalone producer through its
// public crypto surface only (no hosted service code path). This suite drives
// each record's canonical CBOR bytes through this SDK's structural validator
// and the sealed-PoE trial-decrypt, asserting the same interop contract every
// implementation pins: the trial-decrypt verdict, the matched slot index, and
// the recovered CEK bytes. That byte-identity across producers and consumers
// is the cross-implementation invariant.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  eciesSealedPoeTrialDecrypt,
  sealedEnvelopeFromParsed,
  type ParsedEnvelopeShape,
} from '@cardanowall/crypto-core/sealed-poe';
import { validatePoeRecord, type ItemEntry } from '@cardanowall/poe-standard';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(HERE, '../fixtures/cross-service');

interface CrossServiceFixture {
  readonly inputs: Readonly<Record<string, unknown>>;
  readonly record: {
    readonly metadata_cbor_hex: string;
    readonly tx_hash_hex: string;
    readonly block_height: number;
    readonly block_time: number;
    readonly confirmation_depth: number;
  };
  readonly expected: {
    readonly trial_decrypt_kind: string;
    readonly matched_item_idx: number;
    readonly matched_slot_idx: number;
    readonly recovered_cek_hex: string;
  };
}

function loadFixture(filename: string): CrossServiceFixture {
  return JSON.parse(readFileSync(path.join(FIXTURE_DIR, filename), 'utf8')) as CrossServiceFixture;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Validate the record bytes, project the sealed envelope, and run the
// trial-decrypt with the fixture's pinned recipient secret.
function replayFixture(fixture: CrossServiceFixture, recipientSecret: Uint8Array): void {
  // Chain facts travel in their wire representations: block_time is integer
  // POSIX seconds, depth is counted in blocks (tip − block + 1).
  expect(Number.isInteger(fixture.record.block_time)).toBe(true);
  expect(fixture.record.confirmation_depth).toBeGreaterThanOrEqual(1);

  const validation = validatePoeRecord(hexToBytes(fixture.record.metadata_cbor_hex), {
    role: 'recipient_or_strict',
  });
  expect(validation.valid).toBe(true);
  if (!validation.valid) return;

  const items = validation.record.items ?? [];
  expect(items.length).toBe(1);
  const item = items[fixture.expected.matched_item_idx] as ItemEntry;

  const envelope = sealedEnvelopeFromParsed(item.enc as ParsedEnvelopeShape);
  expect(envelope).not.toBeNull();
  if (envelope === null) return;

  const trial = eciesSealedPoeTrialDecrypt({
    envelope,
    hashes: item.hashes,
    recipientSecretKeys: [recipientSecret],
  });
  expect(trial.kind).toBe(fixture.expected.trial_decrypt_kind);
  if (trial.kind !== 'match') return;
  expect(trial.slotIdx).toBe(fixture.expected.matched_slot_idx);
  expect(bytesToHex(trial.cek)).toBe(fixture.expected.recovered_cek_hex);
}

describe('cross-service interop parity', () => {
  it('externally published x25519 sealed record validates and trial-decrypts to the pinned CEK', () => {
    const fixture = loadFixture('external-sealed-record.json');
    const secret = hexToBytes(fixture.inputs['recipient_x25519_secret_key_hex'] as string);
    replayFixture(fixture, secret);
  });

  it('externally published mlkem768x25519 sealed record validates and trial-decrypts to the pinned CEK', () => {
    const fixture = loadFixture('external-sealed-record-hybrid.json');
    const secret = hexToBytes(fixture.inputs['recipient_mlkem768x25519_secret_seed_hex'] as string);
    replayFixture(fixture, secret);
  });
});
