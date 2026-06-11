// Conformance replay — role-dependent envelope dispositions.
//
// Replays the shared enc-unsupported-roles corpus: each vector is one record
// whose `enc` envelope names an identifier outside the implemented set,
// validated under BOTH readings of the unknown-envelope rule. In the default
// public reading the envelope degrades to opaque (`ENC_UNSUPPORTED` at info
// severity, the content-hash claim still validates, and no shape or length
// rule fires against the unknown identifier); the recipient role / strict
// sealed-crypto mode rejects hard, escalating `ENC_UNSUPPORTED` to error and
// co-firing the identifier-specific `UNSUPPORTED_*` code.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { validatePoeRecord, type ValidatorRole } from './validator';

interface RoleExpectation {
  readonly valid: boolean;
  readonly error_codes: ReadonlyArray<string>;
  readonly info_codes: ReadonlyArray<string>;
}

interface RoleVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_by_role: {
    readonly public: RoleExpectation;
    readonly recipient_or_strict: RoleExpectation;
  };
  readonly note?: string;
}

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures',
);

const corpus = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'validator/enc-unsupported-roles.json'), 'utf8'),
) as { vectors: RoleVector[] };

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function assertRole(vector: RoleVector, role: ValidatorRole): void {
  const expected = vector.expected_by_role[role];
  const result = validatePoeRecord(hexToBytes(vector.cbor_hex), { role });
  expect(result.valid).toBe(expected.valid);
  const issues = result.valid
    ? [...(result.warnings ?? []), ...(result.info ?? [])]
    : result.issues;
  const actualErrors = [
    ...new Set(issues.filter((i) => i.severity === 'error').map((i) => i.code)),
  ].sort();
  const actualInfo = [
    ...new Set(issues.filter((i) => i.severity === 'info').map((i) => i.code)),
  ].sort();
  expect(actualErrors).toEqual([...expected.error_codes].sort());
  expect(actualInfo).toEqual([...expected.info_codes].sort());
}

describe('enc-unsupported-roles corpus (dual-severity envelope dispositions)', () => {
  for (const vector of corpus.vectors) {
    it(`${vector.name} — public reading`, () => {
      assertRole(vector, 'public');
    });
    it(`${vector.name} — recipient / strict reading`, () => {
      assertRole(vector, 'recipient_or_strict');
    });
  }
});

describe('role default', () => {
  it('omitting the role option applies the public reading', () => {
    const vector = corpus.vectors[0]!;
    const result = validatePoeRecord(hexToBytes(vector.cbor_hex));
    expect(result.valid).toBe(vector.expected_by_role.public.valid);
  });
});
