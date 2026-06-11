import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { isAssigned16, isWhiteSpace16, Nfkc16Error, nfkc16 } from '../../src/unicode/nfkc16';

interface NfkcOracle {
  ucd_version: string;
  pairs: string[];
  sample_assigned: string[];
  sample_unassigned: string[];
}

interface OraclePair {
  sourceHex: string;
  source: string;
  expected: string;
  parts: readonly string[];
  sourceCodePoints: readonly number[];
}

const here = path.dirname(fileURLToPath(import.meta.url));
const oraclePath = path.resolve(here, '../fixtures/unicode/nfkc-16.0.json');
const oracle = JSON.parse(fs.readFileSync(oraclePath, 'utf8')) as NfkcOracle;

function codePointsFromHex(seq: string): number[] {
  return seq.split(' ').map((token) => parseInt(token, 16));
}

function stringFromHex(seq: string): string {
  return String.fromCodePoint(...codePointsFromHex(seq));
}

function parsePair(line: string): OraclePair {
  const bar = line.indexOf('|');
  const mapping = line.slice(0, bar);
  const semi = mapping.indexOf(';');
  const sourceHex = mapping.slice(0, semi);
  return {
    sourceHex,
    source: stringFromHex(sourceHex),
    expected: stringFromHex(mapping.slice(semi + 1)),
    parts: line.slice(bar + 1).split(' '),
    sourceCodePoints: codePointsFromHex(sourceHex),
  };
}

const pairs = oracle.pairs.map(parsePair);

function expectNfkc16Error(
  run: () => unknown,
  code: 'UNPAIRED_SURROGATE' | 'UNASSIGNED_CODEPOINT',
): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(Nfkc16Error);
    expect((error as Nfkc16Error).code).toBe(code);
    return;
  }
  expect.fail(`expected nfkc16 to throw ${code}`);
}

describe('nfkc16 — Unicode 16.0.0 NormalizationTest oracle', () => {
  it('is pinned to UCD 16.0.0 and carries the full corpus', () => {
    expect(oracle.ucd_version).toBe('16.0.0');
    expect(pairs.length).toBeGreaterThan(30000);
    expect(oracle.sample_assigned.length).toBeGreaterThanOrEqual(40);
    expect(oracle.sample_unassigned.length).toBeGreaterThanOrEqual(40);
  });

  it('replays every oracle pair byte-exactly', () => {
    const failures: string[] = [];
    for (const pair of pairs) {
      const actual = nfkc16(pair.source);
      if (actual !== pair.expected) {
        failures.push(`${pair.sourceHex} -> ${actual} (expected ${pair.expected})`);
        if (failures.length >= 20) break;
      }
    }
    expect(failures).toEqual([]);
  });

  it('keeps unlisted assigned code points NFKC-stable (stratified sample)', () => {
    // NormalizationTest guarantees X == NFKC(X) for every code point that
    // never appears as column 1 of Part 1; replay that invariant over every
    // 17th assigned code point.
    const part1Singles = new Set<number>();
    for (const pair of pairs) {
      if (pair.sourceCodePoints.length === 1 && pair.parts.includes('1')) {
        const cp = pair.sourceCodePoints[0];
        if (cp !== undefined) part1Singles.add(cp);
      }
    }
    expect(part1Singles.size).toBeGreaterThan(5000);

    const failures: string[] = [];
    let assignedSeen = 0;
    let checked = 0;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (!isAssigned16(cp)) continue;
      assignedSeen++;
      if (assignedSeen % 17 !== 0) continue;
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      if (part1Singles.has(cp)) continue;
      const source = String.fromCodePoint(cp);
      checked++;
      if (nfkc16(source) !== source) {
        failures.push(cp.toString(16).toUpperCase());
        if (failures.length >= 20) break;
      }
    }
    expect(failures).toEqual([]);
    expect(checked).toBeGreaterThan(10000);
  });
});

describe('nfkc16 — assigned-at-16.0 guard', () => {
  it('rejects every sampled unassigned code point with a typed error', () => {
    for (const hex of oracle.sample_unassigned) {
      const cp = parseInt(hex, 16);
      expect(isAssigned16(cp)).toBe(false);
      expectNfkc16Error(() => nfkc16(String.fromCodePoint(cp)), 'UNASSIGNED_CODEPOINT');
      expectNfkc16Error(() => nfkc16(`a${String.fromCodePoint(cp)}b`), 'UNASSIGNED_CODEPOINT');
    }
  });

  it('accepts every sampled assigned code point', () => {
    for (const hex of oracle.sample_assigned) {
      const cp = parseInt(hex, 16);
      expect(isAssigned16(cp)).toBe(true);
      expect(() => nfkc16(String.fromCodePoint(cp))).not.toThrow();
    }
  });

  it('reports the offending code point on the error', () => {
    const hex = oracle.sample_unassigned[0];
    if (hex === undefined) expect.fail('oracle sample_unassigned is empty');
    const cp = parseInt(hex, 16);
    try {
      nfkc16(String.fromCodePoint(cp));
      expect.fail('expected nfkc16 to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(Nfkc16Error);
      expect((error as Nfkc16Error).codePoint).toBe(cp);
    }
  });

  it('is total and false outside the code-point space', () => {
    expect(isAssigned16(-1)).toBe(false);
    expect(isAssigned16(0x110000)).toBe(false);
    expect(isAssigned16(0.5)).toBe(false);
  });
});

describe('nfkc16 — UTF-16 well-formedness', () => {
  it('rejects unpaired surrogates wherever they appear', () => {
    expectNfkc16Error(() => nfkc16('\uD800'), 'UNPAIRED_SURROGATE');
    expectNfkc16Error(() => nfkc16('\uDC00'), 'UNPAIRED_SURROGATE');
    expectNfkc16Error(() => nfkc16('a\uD800z'), 'UNPAIRED_SURROGATE');
    expectNfkc16Error(() => nfkc16('a\uD800'), 'UNPAIRED_SURROGATE');
    expectNfkc16Error(() => nfkc16('\uDC00\uD800'), 'UNPAIRED_SURROGATE');
  });

  it('accepts well-formed surrogate pairs for assigned astral code points', () => {
    expect(nfkc16('😀')).toBe('\u{1F600}');
  });

  it('returns the empty string unchanged', () => {
    expect(nfkc16('')).toBe('');
  });
});

describe('isWhiteSpace16 — pinned White_Space property', () => {
  it('matches the Unicode 16.0.0 White_Space set on its boundaries', () => {
    for (const cp of [0x09, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x3000]) {
      expect(isWhiteSpace16(cp)).toBe(true);
    }
    // U+200B ZERO WIDTH SPACE and U+FEFF are not White_Space; engine \s
    // disagrees about U+FEFF, which is exactly why the property is pinned.
    for (const cp of [0x08, 0x0e, 0x21, 0x200b, 0xfeff, 0x3001]) {
      expect(isWhiteSpace16(cp)).toBe(false);
    }
  });
});
