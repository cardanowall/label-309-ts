// Behavioural tests for the cardano-poe-pw-norm-v1 normalization profile:
// pinned-Unicode-16.0 NFKC (with the unnormalizable-input rejection),
// White_Space-run collapse, trim, the empty rejection, and the raw-input
// byte bound.

import { describe, expect, it } from 'vitest';

import { MAX_PASSPHRASE_INPUT_BYTES, normalizePassphrase } from './passphrase-normalize';

const UTF8 = new TextEncoder();

describe('cardano-poe-pw-norm-v1', () => {
  it('passes a plain ASCII passphrase through unchanged', () => {
    expect(normalizePassphrase('correct horse battery staple')).toEqual(
      UTF8.encode('correct horse battery staple'),
    );
  });

  it('applies NFKC: decomposed and precomposed forms derive identical bytes', () => {
    const decomposed = 'Á café'; // A + combining acute, e + combining acute
    const precomposed = 'Á café'; // Á, é
    expect(normalizePassphrase(decomposed)).toEqual(normalizePassphrase(precomposed));
    expect(normalizePassphrase(decomposed)).toEqual(UTF8.encode('Á café'));
  });

  it('applies NFKC compatibility folding (full-width and ligature forms)', () => {
    // Full-width digits (U+FF11..U+FF13) and the U+FB01 ligature fold under NFKC.
    expect(normalizePassphrase('１２３ ﬁn')).toEqual(UTF8.encode('123 fin'));
  });

  it('collapses every maximal White_Space run to one U+0020', () => {
    // Mixed run: TAB + NBSP + ideographic space + LF between words.
    expect(normalizePassphrase('alpha\t\u00A0\u3000\nbeta')).toEqual(UTF8.encode('alpha beta'));
    // Line/paragraph separators and the narrow spaces are White_Space too.
    expect(normalizePassphrase('a\u2028\u2029\u202F\u205Fb')).toEqual(UTF8.encode('a b'));
  });

  it('trims leading and trailing whitespace after collapsing', () => {
    expect(normalizePassphrase('  padded phrase\u3000')).toEqual(UTF8.encode('padded phrase'));
  });

  it('does NOT treat U+FEFF as whitespace (it is not White_Space)', () => {
    expect(normalizePassphrase('a\uFEFFb')).toEqual(UTF8.encode('a\uFEFFb'));
  });

  it('rejects an empty and a whitespace-only passphrase with ENC_PASSPHRASE_EMPTY', () => {
    for (const p of ['', ' ', '\t\n', '\u00A0\u3000', '\u2009  ']) {
      try {
        normalizePassphrase(p);
        throw new Error(`expected ENC_PASSPHRASE_EMPTY for ${JSON.stringify(p)}`);
      } catch (e) {
        expect(e).toMatchObject({ code: 'ENC_PASSPHRASE_EMPTY' });
      }
    }
  });

  it('bounds the RAW UTF-8 input before normalization (PASSPHRASE_INPUT_TOO_LONG)', () => {
    expect(MAX_PASSPHRASE_INPUT_BYTES).toBe(4096);
    // Exactly at the bound: accepted.
    expect(normalizePassphrase('a'.repeat(4096)).length).toBe(4096);
    // One byte over: rejected.
    expect(() => normalizePassphrase('a'.repeat(4097))).toThrowError(
      expect.objectContaining({ code: 'PASSPHRASE_INPUT_TOO_LONG' }),
    );
    // The bound applies to RAW bytes pre-normalization: two-byte chars count
    // at their raw UTF-8 width.
    const twoByte = 'Á'.repeat(2049); // 4098 raw bytes
    expect(() => normalizePassphrase(twoByte)).toThrowError(
      expect.objectContaining({ code: 'PASSPHRASE_INPUT_TOO_LONG' }),
    );
  });

  it('normalization runs in profile order: NFKC first, then whitespace collapse', () => {
    // U+2000 EN QUAD normalizes to U+0020 under NFKC; adjacent to a real space
    // it must still collapse into ONE space, proving collapse runs post-NFKC.
    expect(normalizePassphrase('a\u2000 b')).toEqual(UTF8.encode('a b'));
  });

  it('composes Hangul jamo through the pinned algorithmic path', () => {
    // L+V+T jamo compose to the precomposed syllable U+AC01.
    expect(normalizePassphrase('\u1100\u1161\u11a8')).toEqual(UTF8.encode('\uac01'));
  });

  it('rejects a code point unassigned in Unicode 16.0 with ENC_PASSPHRASE_UNNORMALIZABLE', () => {
    // U+0378 (BMP) and U+1FFFF (supplementary) are unassigned in Unicode 16.0;
    // a later Unicode version could give them decompositions, so accepting
    // them would let the derived key drift across implementations.
    for (const p of ['pass\u0378word', 'tail\u{1FFFF}']) {
      try {
        normalizePassphrase(p);
        throw new Error(`expected ENC_PASSPHRASE_UNNORMALIZABLE for ${JSON.stringify(p)}`);
      } catch (e) {
        expect(e).toMatchObject({ code: 'ENC_PASSPHRASE_UNNORMALIZABLE' });
        expect(e).toMatchObject({ cause: { code: 'UNASSIGNED_CODEPOINT' } });
      }
    }
  });

  it('rejects an unpaired surrogate with ENC_PASSPHRASE_UNNORMALIZABLE', () => {
    for (const p of ['\uD800ab', 'ab\uDC00', 'a\uDBFFb']) {
      try {
        normalizePassphrase(p);
        throw new Error(`expected ENC_PASSPHRASE_UNNORMALIZABLE for ${JSON.stringify(p)}`);
      } catch (e) {
        expect(e).toMatchObject({ code: 'ENC_PASSPHRASE_UNNORMALIZABLE' });
        expect(e).toMatchObject({ cause: { code: 'UNPAIRED_SURROGATE' } });
      }
    }
  });

  it('rejects unnormalizable input before whitespace collapse, trim, and the empty check', () => {
    // Whitespace-only apart from the unassigned code point: were collapse/trim
    // to run first, this would surface ENC_PASSPHRASE_EMPTY.
    expect(() => normalizePassphrase(' \u0378 ')).toThrowError(
      expect.objectContaining({ code: 'ENC_PASSPHRASE_UNNORMALIZABLE' }),
    );
  });

  it('enforces the raw byte cap before the unnormalizable check', () => {
    // U+0378 is 2 UTF-8 bytes, so the raw input is 4098 bytes: over the cap,
    // which fires before the pinned normalizer ever sees the input.
    expect(() => normalizePassphrase('\u0378' + 'a'.repeat(4096))).toThrowError(
      expect.objectContaining({ code: 'PASSPHRASE_INPUT_TOO_LONG' }),
    );
  });
});
