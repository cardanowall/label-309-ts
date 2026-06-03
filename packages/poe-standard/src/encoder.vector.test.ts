// Frozen cross-language canonical-CBOR record vector.
//
// A single maximal CIP-309 v1 record — items (two hashes + ar:// and ipfs://
// uris + a sealed x25519 enc envelope), merkle, supersedes, a detached
// Ed25519 sigs[0].cose_sign1, crit, and extension keys (`x-note`, `x-meta`) —
// is encoded by the REAL encoder and pinned to frozen bytes. The Python SDK
// loads the byte-identical mirror of this fixture and MUST reproduce the same
// `cbor_hex` / `body_cbor_hex`. The fixture is the byte oracle a future
// third-language SDK validates its encoder against.
//
// Extension keys are the load-bearing case: they are part of the canonical map
// and of the signed `record_body`, so an encoder that silently drops them
// produces different bytes and breaks cross-language tx-identity and
// record-level COSE signatures. This vector freezes their presence.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { encodePoeRecord, encodeRecordBodyForSigning } from './encoder';
import type { PoeRecord } from './schema';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(
  here,
  '../../crypto-core/tests/fixtures/poe-record/maximal-record-with-extension-keys.json',
);

interface RecordVectorFixture {
  readonly name: string;
  readonly record: RecordJson;
  readonly cbor_hex: string;
  readonly body_cbor_hex: string;
}

// JSON shape of the logical record: byte-valued fields carry a `_hex` suffix
// and reconstruct to `Uint8Array`; chunked-bytes arrays are arrays of hex
// strings; extension keys are carried verbatim.
interface RecordJson {
  readonly v: 1;
  readonly items?: ReadonlyArray<{
    readonly hashes_hex: Readonly<Record<string, string>>;
    readonly uris?: ReadonlyArray<ReadonlyArray<string>>;
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
    readonly cose_sign1_hex: ReadonlyArray<string>;
    readonly cose_key_hex?: ReadonlyArray<string>;
  }>;
  readonly crit?: ReadonlyArray<string>;
  readonly [extensionKey: string]: unknown;
}

// Top-level JSON keys the reconstructor consumes itself (base fields + their
// `_hex` reconstruction hints). Every OTHER top-level key is a genuine
// extension key (`x-note`, `x-meta`, …) and is copied through verbatim.
const CONSUMED_TOP_KEYS = new Set(['v', 'items', 'merkle', 'supersedes_hex', 'sigs', 'crit']);

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}
function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

// Reconstruct the typed `PoeRecord` (encoder input) from the JSON fixture,
// preserving every extension key verbatim.
function buildRecord(json: RecordJson): PoeRecord {
  const record: Record<string, unknown> = { v: json.v };
  if (json.items) {
    record['items'] = json.items.map((item) => {
      const hashes: Record<string, Uint8Array> = {};
      for (const [alg, digestHex] of Object.entries(item.hashes_hex)) {
        hashes[alg] = fromHex(digestHex);
      }
      const out: Record<string, unknown> = { hashes };
      if (item.uris) out['uris'] = item.uris.map((chunks) => chunks.slice());
      if (item.enc) {
        const enc: Record<string, unknown> = {
          scheme: item.enc.scheme,
          aead: item.enc.aead,
          nonce: fromHex(item.enc.nonce_hex),
        };
        if (item.enc.kem !== undefined) enc['kem'] = item.enc.kem;
        if (item.enc.slots) {
          enc['slots'] = item.enc.slots.map((s) => ({
            epk: fromHex(s.epk_hex),
            wrap: fromHex(s.wrap_hex),
          }));
        }
        if (item.enc.slots_mac_hex !== undefined)
          enc['slots_mac'] = fromHex(item.enc.slots_mac_hex);
        out['enc'] = enc;
      }
      return out;
    });
  }
  if (json.merkle) {
    record['merkle'] = json.merkle.map((m) => ({
      alg: m.alg,
      root: fromHex(m.root_hex),
      leaf_count: m.leaf_count,
    }));
  }
  if (json.supersedes_hex !== undefined) record['supersedes'] = fromHex(json.supersedes_hex);
  if (json.sigs) {
    record['sigs'] = json.sigs.map((s) => {
      const sig: Record<string, unknown> = { cose_sign1: s.cose_sign1_hex.map(fromHex) };
      if (s.cose_key_hex) sig['cose_key'] = s.cose_key_hex.map(fromHex);
      return sig;
    });
  }
  if (json.crit) record['crit'] = json.crit.slice();
  // Extension keys: copy every key the reconstructor did not already consume.
  for (const [key, value] of Object.entries(json)) {
    if (CONSUMED_TOP_KEYS.has(key)) continue;
    record[key] = value;
  }
  return record as PoeRecord;
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as RecordVectorFixture;

describe('encodePoeRecord — frozen cross-language record vector', () => {
  const record = buildRecord(fixture.record);

  it('reproduces the frozen full-record canonical CBOR (cbor_hex)', () => {
    expect(toHex(encodePoeRecord(record))).toBe(fixture.cbor_hex);
  });

  it('reproduces the frozen record-body canonical CBOR (body_cbor_hex, sigs stripped)', () => {
    expect(toHex(encodeRecordBodyForSigning(record))).toBe(fixture.body_cbor_hex);
  });

  it('the frozen record carries the extension keys it pins', () => {
    // Guards the fixture itself: if a future edit drops the extension keys,
    // the vector silently stops testing the encode-extension-key path.
    expect(fixture.record['x-note']).toBeDefined();
    expect(fixture.record['x-meta']).toBeDefined();
    expect(Object.keys(record)).toEqual(expect.arrayContaining(['x-note', 'x-meta']));
  });
});
