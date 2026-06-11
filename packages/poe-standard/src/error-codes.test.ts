// Catalogue invariants for the Label 309 v1 error-code taxonomy.
//
// The TypeScript catalogue is a projection of the canonical machine-readable
// registry; its entry ORDER is load-bearing (same-path issues tie-break by
// registry position), so these tests pin the structural invariants every
// implementation's projection must satisfy.

import { describe, expect, it } from 'vitest';

import {
  CARRIAGE_ERROR_CODES,
  DUAL_SEVERITY_CODES,
  ERROR_CODE_PART,
  ERROR_CODES,
  SEVERITY,
  STRUCTURAL_ERROR_CODES,
  VERIFIER_ERROR_CODES,
  errorCodeRegistryIndex,
  severityOf,
  type ErrorCode,
  type Severity,
} from './error-codes';

describe('catalogue shape', () => {
  it('codes are unique', () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });

  it('every code is SCREAMING_SNAKE_CASE', () => {
    for (const code of ERROR_CODES) {
      expect(code).toMatch(/^[A-Z][A-Z0-9_]*$/);
    }
  });

  it('the per-layer views partition the catalogue in registry order', () => {
    const union = [...STRUCTURAL_ERROR_CODES, ...CARRIAGE_ERROR_CODES, ...VERIFIER_ERROR_CODES];
    expect(union.length).toBe(ERROR_CODES.length);
    expect(new Set(union).size).toBe(ERROR_CODES.length);
    for (const view of [STRUCTURAL_ERROR_CODES, CARRIAGE_ERROR_CODES, VERIFIER_ERROR_CODES]) {
      const indices = view.map((code) => errorCodeRegistryIndex(code));
      expect([...indices].sort((a, b) => a - b)).toEqual(indices);
    }
  });

  it('every code carries a part and a severity', () => {
    for (const code of ERROR_CODES) {
      expect(['A', 'B', 'carriage']).toContain(ERROR_CODE_PART[code]);
      expect(['error', 'warning', 'info']).toContain(SEVERITY[code]);
    }
  });

  it('errorCodeRegistryIndex is the position in ERROR_CODES', () => {
    ERROR_CODES.forEach((code, index) => {
      expect(errorCodeRegistryIndex(code)).toBe(index);
    });
  });
});

describe('layer assignment', () => {
  it('CHUNK_TOO_LARGE is the sole carriage-layer code', () => {
    expect(CARRIAGE_ERROR_CODES).toEqual(['CHUNK_TOO_LARGE']);
  });

  it('the structural validator owns the schema/enc/sig/crit families', () => {
    for (const code of [
      'MALFORMED_CBOR',
      'SCHEMA_EMPTY_RECORD',
      'SCHEMA_MERKLE_LEAF_COUNT_INVALID',
      'ENC_REQUIRES_CONTENT_HASH',
      'ENC_UNSUPPORTED',
      'SIG_PRIVATE_KEY_LEAKED',
      'EXTENSION_UNSUPPORTED_CRITICAL',
      'CRIT_SHAPE_INVALID',
    ] as const) {
      expect(ERROR_CODE_PART[code]).toBe('A');
    }
  });

  it('chain/fetch/decrypt outcomes are verifier-layer codes', () => {
    for (const code of [
      'TX_INTEGRITY_MISMATCH',
      'TX_NOT_FOUND',
      'METADATA_NOT_FOUND',
      'URI_INTEGRITY_MISMATCH',
      'URI_PROVIDER_INTEGRITY_MISMATCH',
      'TAMPERED_CIPHERTEXT',
      'ENC_PASSPHRASE_UNNORMALIZABLE',
      'ENC_PASSPHRASE_EMPTY',
    ] as const) {
      expect(ERROR_CODE_PART[code]).toBe('B');
    }
  });
});

describe('severity contract', () => {
  it('non-failing dispositions carry their pinned default severities', () => {
    expect(severityOf('SIGNATURE_UNSUPPORTED')).toBe<Severity>('info');
    expect(severityOf('ENC_UNSUPPORTED')).toBe<Severity>('info');
    expect(severityOf('INSUFFICIENT_CONFIRMATIONS')).toBe<Severity>('info');
    expect(severityOf('MERKLE_UNSUPPORTED')).toBe<Severity>('info');
    expect(severityOf('OUT_OF_PROFILE_SKIPPED')).toBe<Severity>('info');
    expect(severityOf('URI_FETCH_FAILED')).toBe<Severity>('warning');
    expect(severityOf('URI_PROVIDER_INTEGRITY_MISMATCH')).toBe<Severity>('warning');
    expect(severityOf('MERKLE_LEAVES_UNAVAILABLE')).toBe<Severity>('warning');
  });

  it('the dual-severity set is exactly the four context-promoted codes', () => {
    expect([...DUAL_SEVERITY_CODES].sort()).toEqual([
      'ENC_UNSUPPORTED',
      'MERKLE_LEAVES_UNAVAILABLE',
      'MERKLE_UNSUPPORTED',
      'OUT_OF_PROFILE_SKIPPED',
    ]);
  });

  it('every other code is a hard error or a pinned non-failing disposition', () => {
    for (const code of ERROR_CODES) {
      if (DUAL_SEVERITY_CODES.has(code)) continue;
      if (
        code === 'SIGNATURE_UNSUPPORTED' ||
        code === 'INSUFFICIENT_CONFIRMATIONS' ||
        code === 'URI_FETCH_FAILED' ||
        code === 'URI_PROVIDER_INTEGRITY_MISMATCH'
      ) {
        continue;
      }
      expect(SEVERITY[code]).toBe('error');
    }
  });
});

describe('ErrorCode union (compile-time)', () => {
  it('admits canonical codes and rejects unknown ones', () => {
    const ok: ErrorCode = 'MALFORMED_CBOR';
    expect(ok).toBe('MALFORMED_CBOR');
    // @ts-expect-error 'NOT_A_REAL_CODE' is not in the canonical catalogue
    const bad: ErrorCode = 'NOT_A_REAL_CODE';
    expect(bad).toBe('NOT_A_REAL_CODE');
  });
});
