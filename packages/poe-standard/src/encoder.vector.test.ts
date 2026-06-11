// Frozen cross-language canonical-CBOR record vector.
//
// A single maximal Label 309 v1 record — items (two hashes + ar:// and ipfs://
// URIs as single text strings + a shape-valid sealed x25519 envelope), merkle,
// supersedes, a detached Ed25519 sigs[0].cose_sign1 carried as a single byte
// string, crit, and extension keys (`x-note`, `x-meta`) — is encoded by the
// REAL encoder and pinned to frozen bytes. The Python and Rust SDKs load the
// byte-identical mirror of this fixture and MUST reproduce the same
// `cbor_hex` / `body_cbor_hex`; the fixture is the byte oracle any
// third-language encoder validates against.
//
// Extension keys are the load-bearing case: they are part of the canonical
// map and of the signed record body, so an encoder that silently drops them
// produces different bytes and breaks cross-language tx-identity and
// record-level COSE signatures. This vector freezes their presence.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { encodePoeRecord, encodeRecordBodyForSigning } from './encoder';
import type { PoeRecord } from './schema';
import { validatePoeRecord } from './validator';

const fixturePath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures/poe-record/maximal-record-with-extension-keys.json',
);

interface RecordVectorFixture {
  readonly name: string;
  readonly validator_options?: { readonly supportedCriticalExtensions?: string[] };
  readonly record: RecordJson;
  readonly cbor_hex: string;
  readonly body_cbor_hex: string;
}

// JSON projection of the logical record: byte-valued fields carry a `_hex`
// suffix and reconstruct to `Uint8Array`; every other field carries its wire
// value verbatim (each URI one string, `leaf_count` an integer, extension
// keys as-is).
interface RecordJson {
  readonly v: 1;
  readonly items?: ReadonlyArray<{
    readonly hashes_hex: Readonly<Record<string, string>>;
    readonly uris?: ReadonlyArray<string>;
    readonly enc?: {
      readonly scheme: number;
      readonly aead: string;
      readonly kem?: string;
      readonly nonce_hex: string;
      readonly slots?: ReadonlyArray<{ readonly epk_hex: string; readonly wrap_hex: string }>;
      readonly slots_mac_hex?: string;
    };
  }>;
  readonly merkle?: ReadonlyArray<{
    readonly alg: string;
    readonly root_hex: string;
    readonly leaf_count: number;
  }>;
  readonly supersedes_hex?: string;
  readonly sigs?: ReadonlyArray<{
    readonly cose_sign1_hex: string;
    readonly cose_key_hex?: string;
  }>;
  readonly crit?: ReadonlyArray<string>;
  readonly [extension: string]: unknown;
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as RecordVectorFixture;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

const KNOWN_RECORD_KEYS = new Set(['v', 'items', 'merkle', 'supersedes_hex', 'sigs', 'crit']);

function recordFromJson(json: RecordJson): PoeRecord {
  const record: Record<string, unknown> = { v: json.v };
  if (json.items !== undefined) {
    record['items'] = json.items.map((item) => {
      const hashes: Record<string, Uint8Array> = {};
      for (const [alg, digestHex] of Object.entries(item.hashes_hex)) {
        hashes[alg] = hexToBytes(digestHex);
      }
      const out: Record<string, unknown> = { hashes };
      if (item.uris !== undefined) out['uris'] = [...item.uris];
      if (item.enc !== undefined) {
        const enc: Record<string, unknown> = {
          scheme: item.enc.scheme,
          aead: item.enc.aead,
          nonce: hexToBytes(item.enc.nonce_hex),
        };
        if (item.enc.kem !== undefined) enc['kem'] = item.enc.kem;
        if (item.enc.slots !== undefined) {
          enc['slots'] = item.enc.slots.map((slot) => ({
            epk: hexToBytes(slot.epk_hex),
            wrap: hexToBytes(slot.wrap_hex),
          }));
        }
        if (item.enc.slots_mac_hex !== undefined) {
          enc['slots_mac'] = hexToBytes(item.enc.slots_mac_hex);
        }
        out['enc'] = enc;
      }
      return out;
    });
  }
  if (json.merkle !== undefined) {
    record['merkle'] = json.merkle.map((commit) => ({
      alg: commit.alg,
      root: hexToBytes(commit.root_hex),
      leaf_count: commit.leaf_count,
    }));
  }
  if (json.supersedes_hex !== undefined) record['supersedes'] = hexToBytes(json.supersedes_hex);
  if (json.sigs !== undefined) {
    record['sigs'] = json.sigs.map((entry) => {
      const out: Record<string, unknown> = { cose_sign1: hexToBytes(entry.cose_sign1_hex) };
      if (entry.cose_key_hex !== undefined) out['cose_key'] = hexToBytes(entry.cose_key_hex);
      return out;
    });
  }
  if (json.crit !== undefined) record['crit'] = [...json.crit];
  for (const [key, value] of Object.entries(json)) {
    if (!KNOWN_RECORD_KEYS.has(key)) record[key] = value;
  }
  return record as PoeRecord;
}

describe('maximal-record-with-extension-keys (frozen byte vector)', () => {
  const record = recordFromJson(fixture.record);

  it('encodePoeRecord reproduces the frozen record bytes', () => {
    expect(bytesToHex(encodePoeRecord(record))).toBe(fixture.cbor_hex);
  });

  it('encodeRecordBodyForSigning reproduces the frozen sigs-removed body bytes', () => {
    expect(bytesToHex(encodeRecordBodyForSigning(record))).toBe(fixture.body_cbor_hex);
  });

  it('the frozen bytes validate under the fixture validator options', () => {
    const result = validatePoeRecord(hexToBytes(fixture.cbor_hex), {
      supportedCriticalExtensions: new Set(
        fixture.validator_options?.supportedCriticalExtensions ?? [],
      ),
    });
    expect(result.valid).toBe(true);
  });

  it('the frozen bytes fail under the default empty crit set (the record carries crit)', () => {
    const result = validatePoeRecord(hexToBytes(fixture.cbor_hex));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => issue.code)).toContain('EXTENSION_UNSUPPORTED_CRITICAL');
  });
});
