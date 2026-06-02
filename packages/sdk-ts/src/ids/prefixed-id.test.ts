import { describe, expect, it } from 'vitest';

import { decodePrefixedId, encodePrefixedId, isPrefixedId } from './prefixed-id';

const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const MAX_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const SAMPLE_UUIDV7 = '01977c4a-0066-7777-aaaa-bbbbbbbbbbbb';

describe('encodePrefixedId', () => {
  it('produces `<prefix>_<26-char-base32>` for a real UUID', () => {
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(encoded.startsWith('poe_')).toBe(true);
    expect(encoded.slice(4)).toHaveLength(26);
    expect(/^[0-9a-hjkmnp-tv-z]{26}$/.test(encoded.slice(4))).toBe(true);
  });

  it('round-trips the nil UUID', () => {
    const encoded = encodePrefixedId('acct', NIL_UUID);
    expect(encoded).toBe(`acct_${'0'.repeat(26)}`);
    expect(decodePrefixedId('acct', encoded)).toBe(NIL_UUID);
  });

  it('round-trips the max UUID', () => {
    const encoded = encodePrefixedId('inv', MAX_UUID);
    expect(decodePrefixedId('inv', encoded)).toBe(MAX_UUID);
  });

  it('round-trips an arbitrary UUIDv7', () => {
    const encoded = encodePrefixedId('apikey', SAMPLE_UUIDV7);
    expect(decodePrefixedId('apikey', encoded)).toBe(SAMPLE_UUIDV7);
  });

  it('rejects malformed UUIDs', () => {
    expect(() => encodePrefixedId('poe', 'not-a-uuid')).toThrow(/canonical hyphenated UUID/);
    // No hyphens
    expect(() => encodePrefixedId('poe', '01977c4a00667777aaaabbbbbbbbbbbb')).toThrow();
    // Wrong width
    expect(() => encodePrefixedId('poe', '01977c4a-0066-7777-aaaa-bbbbbbbbbbb')).toThrow();
  });
});

describe('decodePrefixedId', () => {
  it('rejects mismatched prefix', () => {
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(() => decodePrefixedId('acct', encoded)).toThrow(/expected prefix "acct"/);
  });

  it('rejects missing separator', () => {
    expect(() => decodePrefixedId('poe', 'poenoseparatorhere00000000000000')).toThrow(
      /missing prefix separator/,
    );
  });

  it('rejects body of wrong length', () => {
    expect(() => decodePrefixedId('poe', 'poe_tooshort')).toThrow(/26-char input/);
    expect(() => decodePrefixedId('poe', `poe_${'a'.repeat(27)}`)).toThrow(/26-char input/);
  });

  it('rejects body with invalid base32 characters', () => {
    expect(() => decodePrefixedId('poe', `poe_${'!'.repeat(26)}`)).toThrow(/invalid character/);
  });

  it('rejects non-string input', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => decodePrefixedId('poe', 42 as any)).toThrow(/expected string/);
  });
});

describe('isPrefixedId', () => {
  it('accepts canonical lowercase wire form', () => {
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(isPrefixedId('poe', encoded)).toBe(true);
  });

  it('rejects mismatched prefix', () => {
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(isPrefixedId('acct', encoded)).toBe(false);
  });

  it('rejects bare UUIDs', () => {
    expect(isPrefixedId('poe', SAMPLE_UUIDV7)).toBe(false);
  });

  it('rejects uppercase characters in the body', () => {
    // isPrefixedId checks the strict lowercase wire form — accepting both
    // cases is decodePrefixedId's job, not the cheap guard's.
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(isPrefixedId('poe', encoded.toUpperCase())).toBe(false);
  });

  it('rejects I/L/O/U disambiguation aliases (canonical wire = no aliases)', () => {
    const body = '0'.repeat(26);
    expect(isPrefixedId('poe', `poe_${body.slice(0, 5)}I${body.slice(6)}`)).toBe(false);
    expect(isPrefixedId('poe', `poe_${body.slice(0, 5)}o${body.slice(6)}`)).toBe(false);
    expect(isPrefixedId('poe', `poe_${body.slice(0, 5)}u${body.slice(6)}`)).toBe(false);
  });

  it('rejects non-string input', () => {
    expect(isPrefixedId('poe', 42)).toBe(false);
    expect(isPrefixedId('poe', null)).toBe(false);
    expect(isPrefixedId('poe', undefined)).toBe(false);
  });

  it('rejects a canonical id with a trailing newline (parity with sdk-py fullmatch)', () => {
    // Python's regex `$` matches just before a final `\n`, so the Python guard
    // must use `re.fullmatch` to reject `poe_…\n`. TS already rejects it (the
    // `^…$` anchor plus the `body.length === 26` check). This pins the TS side
    // of that parity contract.
    const encoded = encodePrefixedId('poe', SAMPLE_UUIDV7);
    expect(isPrefixedId('poe', encoded)).toBe(true);
    expect(isPrefixedId('poe', `${encoded}\n`)).toBe(false);
  });
});
