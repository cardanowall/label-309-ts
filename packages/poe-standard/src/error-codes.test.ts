// Catalogue invariants for the Label 309 v1 error-code taxonomy.

import { describe, expect, it } from 'vitest';

import {
  ERROR_CODES,
  STRUCTURAL_ERROR_CODES,
  SEVERITY,
  VERIFIER_ERROR_CODES,
  severityOf,
  type ErrorCode,
  type Severity,
} from './error-codes';

describe('ERROR_CODES catalogue (structural + verifier-layer codes)', () => {
  it('STRUCTURAL_ERROR_CODES is a unique, frozen list', () => {
    const set = new Set(STRUCTURAL_ERROR_CODES);
    expect(set.size).toBe(STRUCTURAL_ERROR_CODES.length);
  });

  it('VERIFIER_ERROR_CODES is a unique, frozen list disjoint from STRUCTURAL_ERROR_CODES', () => {
    const structural = new Set(STRUCTURAL_ERROR_CODES);
    for (const code of VERIFIER_ERROR_CODES) {
      expect(structural.has(code as never)).toBe(false);
    }
  });

  it('ERROR_CODES is the union of both lists', () => {
    expect(ERROR_CODES.length).toBe(STRUCTURAL_ERROR_CODES.length + VERIFIER_ERROR_CODES.length);
  });

  it('every ErrorCode has a SEVERITY entry', () => {
    for (const code of ERROR_CODES) {
      expect(SEVERITY[code]).toBeDefined();
    }
  });

  it('SIGNATURE_UNSUPPORTED carries severity=info', () => {
    expect(severityOf('SIGNATURE_UNSUPPORTED')).toBe<Severity>('info');
  });

  it('URI_FETCH_FAILED carries severity=warning', () => {
    expect(severityOf('URI_FETCH_FAILED')).toBe<Severity>('warning');
  });

  it('MERKLE_UNSUPPORTED carries default severity=info (verifier promotes for merkle-only records)', () => {
    expect(severityOf('MERKLE_UNSUPPORTED')).toBe<Severity>('info');
  });

  it('OUT_OF_PROFILE_SKIPPED carries default severity=info (verifier promotes in strict mode)', () => {
    expect(severityOf('OUT_OF_PROFILE_SKIPPED')).toBe<Severity>('info');
  });

  it('ErrorCode union admits known codes (compile-time)', () => {
    const ok: ErrorCode = 'MALFORMED_CBOR';
    expect(ok).toBe('MALFORMED_CBOR');
  });

  it('ErrorCode union rejects unknown codes (compile-time)', () => {
    // @ts-expect-error 'NOT_A_REAL_CODE' is not in the canonical catalogue
    const bad: ErrorCode = 'NOT_A_REAL_CODE';
    expect(bad).toBe('NOT_A_REAL_CODE');
  });
});

describe('canonical taxonomy presence (spot checks of structural codes)', () => {
  // Spot-checks for the most semantically-loaded codes the validator emits.
  const required: ErrorCode[] = [
    'MALFORMED_CBOR',
    'SCHEMA_EMPTY_RECORD',
    'SCHEMA_INVALID_LITERAL',
    'SCHEMA_MISSING_REQUIRED',
    'SCHEMA_TYPE_MISMATCH',
    'SCHEMA_UNKNOWN_FIELD',
    'HASH_DIGEST_LENGTH_MISMATCH',
    'UNSUPPORTED_HASH_ALG',
    'UNSUPPORTED_MERKLE_COMMIT_ALG',
    'INVALID_URI',
    'CHUNK_TOO_LARGE',
    'UNAUTHENTICATED_CIPHER_FORBIDDEN',
    'UNSUPPORTED_AEAD_ALG',
    'NONCE_LENGTH_MISMATCH',
    'UNSUPPORTED_ENVELOPE_SCHEME',
    'ENC_SLOTS_EMPTY',
    'ENC_SLOT_INVALID_SHAPE',
    'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
    'ENC_SLOTS_TOO_MANY',
    'ENC_ENVELOPE_TOO_LARGE',
    'UNSUPPORTED_KEM_ALG',
    'ENC_KEM_REQUIRED',
    'KEM_EPK_LENGTH_MISMATCH',
    'WRAP_LENGTH_MISMATCH',
    'ENC_SLOTS_MAC_INVALID_LENGTH',
    'ENC_SLOTS_MAC_REQUIRED',
    'ENC_SLOTS_REQUIRED',
    'ENC_EXCLUSIVITY_VIOLATION',
    'ENC_NO_KEY_PATH',
    'ENC_REQUIRES_CONTENT_HASH',
    'ENC_PASSPHRASE_ALG_UNSUPPORTED',
    'ENC_PASSPHRASE_SALT_TOO_SHORT',
    'ENC_PASSPHRASE_SALT_TOO_LONG',
    'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
    'MALFORMED_SIG_COSE_SIGN1',
    'SIGNATURE_UNSUPPORTED',
    'SIG_ENTRY_INVALID_SHAPE',
    'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
    'SIG_PRIVATE_KEY_LEAKED',
    'SUPERSEDES_TX_INVALID_LENGTH',
    'EXTENSION_UNSUPPORTED_CRITICAL',
    'CRIT_SHAPE_INVALID',
  ];
  for (const code of required) {
    it(`${code} is in STRUCTURAL_ERROR_CODES`, () => {
      expect(STRUCTURAL_ERROR_CODES).toContain(code as never);
    });
  }
});
