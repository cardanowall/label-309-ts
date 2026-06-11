// Pinned Unicode 16.0.0 NFKC normalization.
//
// Keys derived from passphrases must come out identical in every conformant
// implementation, today and years from now, so this module never delegates to
// the host engine's String.prototype.normalize — those tables float with the
// runtime's Unicode version, and two engines on different versions can derive
// different keys from the same passphrase. The tables here are generated from
// the Unicode 16.0.0 UCD and pinned. Code points that Unicode 16.0 leaves
// unassigned are rejected outright: the Unicode stability policy only
// guarantees normalization stability for code points that are assigned in the
// pinned version, so passing unassigned input through would re-open the drift.
//
// Algorithm (UAX #15, no quick-check fast path): validate scalar values and
// the assigned-at-16.0 guard, fully decompose through the flat NFKD table
// (recursion was resolved at table-generation time; Hangul is algorithmic),
// canonically reorder by combining class, then canonically compose (pair
// table with composition exclusions applied, plus algorithmic Hangul).

import {
  NFKC16_ASSIGNED_RANGES_PACKED,
  NFKC16_CCC_PACKED,
  NFKC16_COMPOSITION_PACKED,
  NFKC16_DECOMPOSITION_PACKED,
  NFKC16_WHITE_SPACE_RANGES_PACKED,
} from './nfkc16-data';

export type Nfkc16ErrorCode = 'UNPAIRED_SURROGATE' | 'UNASSIGNED_CODEPOINT';

export class Nfkc16Error extends Error {
  readonly code: Nfkc16ErrorCode;
  /** The offending code point (for UNPAIRED_SURROGATE, the lone surrogate code unit). */
  readonly codePoint: number;

  constructor(code: Nfkc16ErrorCode, message: string, codePoint: number) {
    super(message);
    this.name = 'Nfkc16Error';
    this.code = code;
    this.codePoint = codePoint;
  }
}

// Hangul decomposition/composition is algorithmic (UAX #15 section 3.12).
const HANGUL_S_BASE = 0xac00;
const HANGUL_L_BASE = 0x1100;
const HANGUL_V_BASE = 0x1161;
const HANGUL_T_BASE = 0x11a7;
const HANGUL_L_COUNT = 19;
const HANGUL_V_COUNT = 21;
const HANGUL_T_COUNT = 28;
const HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT; // 588
const HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT; // 11172

const MAX_CODE_POINT = 0x10ffff;

// Composition pairs are keyed as starter * 2^21 + combining; both halves are
// scalar values (<= 0x10FFFF < 2^21), so the packed key stays an exact integer.
const COMPOSITION_KEY_SHIFT = 0x200000;

interface Nfkc16Tables {
  readonly decomposition: ReadonlyMap<number, readonly number[]>;
  readonly ccc: ReadonlyMap<number, number>;
  readonly composition: ReadonlyMap<number, number>;
  /** Flat sorted [start0, end0, start1, end1, ...] pairs for binary search. */
  readonly assignedRanges: Uint32Array;
  readonly whiteSpaceRanges: Uint32Array;
}

function parseDecomposition(packed: string): Map<number, readonly number[]> {
  const out = new Map<number, readonly number[]>();
  for (const entry of packed.split(';')) {
    const eq = entry.indexOf('=');
    const cp = parseInt(entry.slice(0, eq), 16);
    const targets = entry
      .slice(eq + 1)
      .split(' ')
      .map((token) => parseInt(token, 16));
    out.set(cp, targets);
  }
  return out;
}

function parseCcc(packed: string): Map<number, number> {
  const out = new Map<number, number>();
  for (const entry of packed.split(';')) {
    const colon = entry.indexOf(':');
    const value = parseInt(entry.slice(colon + 1), 16);
    const span = entry.slice(0, colon);
    const dash = span.indexOf('-');
    const first = parseInt(dash < 0 ? span : span.slice(0, dash), 16);
    const last = dash < 0 ? first : parseInt(span.slice(dash + 1), 16);
    for (let cp = first; cp <= last; cp++) out.set(cp, value);
  }
  return out;
}

function parseComposition(packed: string): Map<number, number> {
  const out = new Map<number, number>();
  for (const entry of packed.split(';')) {
    const eq = entry.indexOf('=');
    const space = entry.indexOf(' ');
    const starter = parseInt(entry.slice(0, space), 16);
    const combining = parseInt(entry.slice(space + 1, eq), 16);
    out.set(starter * COMPOSITION_KEY_SHIFT + combining, parseInt(entry.slice(eq + 1), 16));
  }
  return out;
}

function parseRanges(packed: string): Uint32Array {
  const entries = packed.split(';');
  const out = new Uint32Array(entries.length * 2);
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i] ?? '';
    const dash = entry.indexOf('-');
    const first = parseInt(dash < 0 ? entry : entry.slice(0, dash), 16);
    const last = dash < 0 ? first : parseInt(entry.slice(dash + 1), 16);
    out[i * 2] = first;
    out[i * 2 + 1] = last;
  }
  return out;
}

let cachedTables: Nfkc16Tables | undefined;

function tables(): Nfkc16Tables {
  cachedTables ??= {
    decomposition: parseDecomposition(NFKC16_DECOMPOSITION_PACKED),
    ccc: parseCcc(NFKC16_CCC_PACKED),
    composition: parseComposition(NFKC16_COMPOSITION_PACKED),
    assignedRanges: parseRanges(NFKC16_ASSIGNED_RANGES_PACKED),
    whiteSpaceRanges: parseRanges(NFKC16_WHITE_SPACE_RANGES_PACKED),
  };
  return cachedTables;
}

function inRanges(ranges: Uint32Array, codePoint: number): boolean {
  let lo = 0;
  let hi = ranges.length / 2 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    // The fallbacks are unreachable (mid is in bounds) and fail closed.
    const start = ranges[mid * 2] ?? Number.MAX_SAFE_INTEGER;
    const end = ranges[mid * 2 + 1] ?? -1;
    if (codePoint < start) hi = mid - 1;
    else if (codePoint > end) lo = mid + 1;
    else return true;
  }
  return false;
}

/** Whether the code point is assigned (General_Category != Cn) in Unicode 16.0.0. */
export function isAssigned16(codePoint: number): boolean {
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > MAX_CODE_POINT) return false;
  return inRanges(tables().assignedRanges, codePoint);
}

/** Whether the code point has White_Space=Yes in Unicode 16.0.0. */
export function isWhiteSpace16(codePoint: number): boolean {
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > MAX_CODE_POINT) return false;
  return inRanges(tables().whiteSpaceRanges, codePoint);
}

function unpairedSurrogate(unit: number, index: number): Nfkc16Error {
  return new Nfkc16Error(
    'UNPAIRED_SURROGATE',
    `unpaired surrogate 0x${unit.toString(16).toUpperCase()} at UTF-16 index ${index}`,
    unit,
  );
}

/**
 * Decode the input into Unicode scalar values, rejecting lone surrogates, and
 * enforce the assigned-at-16.0 guard. Errors are raised in input order.
 */
function validatedScalarValues(input: string, t: Nfkc16Tables): number[] {
  const codePoints: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const unit = input.charCodeAt(i);
    let codePoint = unit;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) throw unpairedSurrogate(unit, i);
      codePoint = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw unpairedSurrogate(unit, i);
    }
    if (!inRanges(t.assignedRanges, codePoint)) {
      throw new Nfkc16Error(
        'UNASSIGNED_CODEPOINT',
        `code point U+${codePoint.toString(16).toUpperCase().padStart(4, '0')} is not assigned in Unicode 16.0.0`,
        codePoint,
      );
    }
    codePoints.push(codePoint);
  }
  return codePoints;
}

function cccOf(t: Nfkc16Tables, codePoint: number): number {
  return t.ccc.get(codePoint) ?? 0;
}

function decompose(t: Nfkc16Tables, codePoints: readonly number[]): number[] {
  const out: number[] = [];
  for (const cp of codePoints) {
    if (cp >= HANGUL_S_BASE && cp < HANGUL_S_BASE + HANGUL_S_COUNT) {
      const sIndex = cp - HANGUL_S_BASE;
      out.push(HANGUL_L_BASE + Math.floor(sIndex / HANGUL_N_COUNT));
      out.push(HANGUL_V_BASE + Math.floor((sIndex % HANGUL_N_COUNT) / HANGUL_T_COUNT));
      const trailing = sIndex % HANGUL_T_COUNT;
      if (trailing !== 0) out.push(HANGUL_T_BASE + trailing);
      continue;
    }
    const mapped = t.decomposition.get(cp);
    if (mapped !== undefined) {
      for (const target of mapped) out.push(target);
    } else {
      out.push(cp);
    }
  }
  return out;
}

/** Canonical Ordering Algorithm: stable insertion sort of nonzero-ccc runs. */
function canonicalReorder(t: Nfkc16Tables, codePoints: number[]): void {
  for (let i = 1; i < codePoints.length; i++) {
    const cp = codePoints[i];
    if (cp === undefined) break; // unreachable: i < length
    const combining = cccOf(t, cp);
    if (combining === 0) continue;
    let j = i;
    while (j > 0) {
      const prev = codePoints[j - 1];
      if (prev === undefined || cccOf(t, prev) <= combining) break;
      codePoints[j] = prev;
      j--;
    }
    codePoints[j] = cp;
  }
}

function composePair(t: Nfkc16Tables, a: number, b: number): number | undefined {
  if (
    a >= HANGUL_L_BASE &&
    a < HANGUL_L_BASE + HANGUL_L_COUNT &&
    b >= HANGUL_V_BASE &&
    b < HANGUL_V_BASE + HANGUL_V_COUNT
  ) {
    return (
      HANGUL_S_BASE + ((a - HANGUL_L_BASE) * HANGUL_V_COUNT + (b - HANGUL_V_BASE)) * HANGUL_T_COUNT
    );
  }
  if (
    a >= HANGUL_S_BASE &&
    a < HANGUL_S_BASE + HANGUL_S_COUNT &&
    (a - HANGUL_S_BASE) % HANGUL_T_COUNT === 0 &&
    b > HANGUL_T_BASE &&
    b < HANGUL_T_BASE + HANGUL_T_COUNT
  ) {
    return a + (b - HANGUL_T_BASE);
  }
  return t.composition.get(a * COMPOSITION_KEY_SHIFT + b);
}

/**
 * Canonical Composition Algorithm. A combining character composes with the
 * last starter when it is not blocked: either it directly follows the starter,
 * or every character in between has a strictly lower combining class (the
 * sequence is canonically ordered, so checking the immediately preceding
 * class suffices). Primary composites are always starters, so a successful
 * composition never changes the trailing combining class.
 */
function compose(t: Nfkc16Tables, codePoints: readonly number[]): number[] {
  const out: number[] = [];
  let starterIdx = -1;
  let lastCcc = 0;
  for (const cp of codePoints) {
    const combining = cccOf(t, cp);
    if (starterIdx >= 0 && (starterIdx === out.length - 1 || lastCcc < combining)) {
      const starter = out[starterIdx];
      const composed = starter === undefined ? undefined : composePair(t, starter, cp);
      if (composed !== undefined) {
        out[starterIdx] = composed;
        continue;
      }
    }
    out.push(cp);
    lastCcc = combining;
    if (combining === 0) starterIdx = out.length - 1;
  }
  return out;
}

function codePointsToString(codePoints: readonly number[]): string {
  let out = '';
  // Chunked to stay clear of engine argument-count limits on long inputs.
  for (let i = 0; i < codePoints.length; i += 1024) {
    out += String.fromCodePoint(...codePoints.slice(i, i + 1024));
  }
  return out;
}

/**
 * Normalize to NFKC exactly as Unicode 16.0.0 defines it.
 *
 * Throws {@link Nfkc16Error} with code UNPAIRED_SURROGATE when the input is
 * not a well-formed UTF-16 string, and with code UNASSIGNED_CODEPOINT when it
 * contains a code point that Unicode 16.0.0 leaves unassigned (normalization
 * of such input would not be stable across Unicode versions).
 */
export function nfkc16(input: string): string {
  const t = tables();
  const codePoints = validatedScalarValues(input, t);
  const decomposed = decompose(t, codePoints);
  canonicalReorder(t, decomposed);
  return codePointsToString(compose(t, decomposed));
}
