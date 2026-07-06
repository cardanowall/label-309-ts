// Frozen cross-language co-hash content-item vector.
//
// One hash-only content item co-hashed under sha2-256 AND blake2b-256. The
// canonical CBOR encoder sorts the two-entry `hashes` map length-first
// (`sha2-256` (8 bytes) before `blake2b-256` (11 bytes)), so the encoded record
// is INDEPENDENT of the order the caller inserted the algorithms. This vector
// pins that order-independence and freezes the bytes the Rust and Python twins
// must reproduce from the byte-identical fixture. The digests are also checked
// to derive from the content, so the fixture is a complete producer oracle for
// the co-hash path (`publishContent` / the sealed co-hash helpers build the
// identical item).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { blake2b256, sha256 } from '@cardanowall/crypto-core/hash';

import { encodePoeRecord } from './encoder';
import type { PoeRecord } from './schema';

const fixturePath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures/poe-record/cohash-item-record.json',
);

interface CohashItemRecordFixture {
  readonly description: string;
  readonly content_hex: string;
  readonly hashes: { readonly 'sha2-256': string; readonly 'blake2b-256': string };
  readonly cbor_hex: string;
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as CohashItemRecordFixture;

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

describe('cohash-item-record (frozen byte vector)', () => {
  const sha = hexToBytes(fixture.hashes['sha2-256']);
  const blake = hexToBytes(fixture.hashes['blake2b-256']);

  it('the pinned digests derive from the content', () => {
    const content = hexToBytes(fixture.content_hex);
    expect(bytesToHex(sha256(content))).toBe(fixture.hashes['sha2-256']);
    expect(bytesToHex(blake2b256(content))).toBe(fixture.hashes['blake2b-256']);
  });

  it('encodes to the frozen bytes with sha2-256 inserted first', () => {
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': sha, 'blake2b-256': blake } }],
    };
    expect(bytesToHex(encodePoeRecord(record))).toBe(fixture.cbor_hex);
  });

  it('encodes to the same frozen bytes with blake2b-256 inserted first', () => {
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'blake2b-256': blake, 'sha2-256': sha } }],
    };
    expect(bytesToHex(encodePoeRecord(record))).toBe(fixture.cbor_hex);
  });
});
