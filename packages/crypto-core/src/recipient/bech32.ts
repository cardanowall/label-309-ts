// Minimal BIP-173 bech32 encoder used to format age-style recipient strings.
//
// This package's dependency policy keeps the runtime import graph to a small,
// audited set of cryptographic libraries, so we inline the exact bech32
// algorithm here rather than pull in a general-purpose base-encoding library.
// Output is byte-identical to the no-length-limit form of a standard bech32
// encoder (`encode(hrp, toWords(bytes))` with the 90-char BIP-173 cap
// disabled): age recipients exceed that cap — an X-Wing recipient is ~1960
// characters — so the limit must be off.

const BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const POLYMOD_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const ENCODING_CONST = 1; // BIP-173 bech32 (not bech32m).

function polymodStep(pre: number): number {
  const b = pre >> 25;
  let chk = (pre & 0x1ffffff) << 5;
  for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
    if (((b >> i) & 1) === 1) chk ^= POLYMOD_GENERATORS[i]!;
  }
  return chk;
}

// 8-bit bytes → 5-bit words, padding the final partial group with zero bits.
function bytesToWords(bytes: Uint8Array): number[] {
  const words: number[] = [];
  let carry = 0;
  let pos = 0;
  const mask = (1 << 5) - 1;
  for (const n of bytes) {
    carry = (carry << 8) | n;
    pos += 8;
    for (; pos >= 5; pos -= 5) words.push((carry >> (pos - 5)) & mask);
    carry &= (1 << pos) - 1;
  }
  if (pos > 0) words.push((carry << (5 - pos)) & mask);
  return words;
}

function checksum(prefix: string, words: number[]): string {
  let chk = 1;
  for (let i = 0; i < prefix.length; i++) {
    const c = prefix.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error(`bech32: invalid prefix (${prefix})`);
    chk = polymodStep(chk) ^ (c >> 5);
  }
  chk = polymodStep(chk);
  for (let i = 0; i < prefix.length; i++) chk = polymodStep(chk) ^ (prefix.charCodeAt(i) & 0x1f);
  for (const v of words) chk = polymodStep(chk) ^ v;
  for (let i = 0; i < 6; i++) chk = polymodStep(chk);
  chk ^= ENCODING_CONST;
  let out = '';
  for (let i = 0; i < 6; i++) out += BECH32_ALPHABET[(chk >> (5 * (5 - i))) & 31];
  return out;
}

// Encode raw bytes to a bech32 string with NO length limit. `prefix` is the HRP.
export function bech32EncodeNoLimit(prefix: string, bytes: Uint8Array): string {
  if (prefix.length === 0) throw new Error('bech32: empty prefix');
  const words = bytesToWords(bytes);
  let payload = '';
  for (const w of words) payload += BECH32_ALPHABET[w];
  const lowered = prefix.toLowerCase();
  return `${lowered}1${payload}${checksum(lowered, words)}`;
}

// Recompute the polymod over the HRP + every data word (the trailing six being
// the checksum) and test it against the encoding constant. True iff the string
// carries a valid bech32 checksum.
function checksumValid(prefix: string, words: number[]): boolean {
  let chk = 1;
  for (let i = 0; i < prefix.length; i++) chk = polymodStep(chk) ^ (prefix.charCodeAt(i) >> 5);
  chk = polymodStep(chk);
  for (let i = 0; i < prefix.length; i++) chk = polymodStep(chk) ^ (prefix.charCodeAt(i) & 0x1f);
  for (const v of words) chk = polymodStep(chk) ^ v;
  return chk === ENCODING_CONST;
}

// 5-bit words → 8-bit bytes (the inverse of `bytesToWords`). Rejects
// non-canonical padding: any leftover must be fewer than 5 bits and all zero,
// matching the zero-fill `bytesToWords` applies to a final partial group.
function wordsToBytes(words: number[]): Uint8Array {
  const out: number[] = [];
  let carry = 0;
  let pos = 0;
  for (const w of words) {
    carry = (carry << 5) | w;
    pos += 5;
    for (; pos >= 8; pos -= 8) out.push((carry >> (pos - 8)) & 0xff);
    carry &= (1 << pos) - 1;
  }
  if (pos >= 5 || carry !== 0) throw new Error('bech32: non-canonical padding');
  return Uint8Array.from(out);
}

// Decode a bech32 string with NO length limit, verifying the checksum. Returns
// the lower-cased HRP and the decoded data bytes. The inverse of
// `bech32EncodeNoLimit`. The separator is the last `1` in the string, so HRPs
// that themselves contain a `1` (e.g. the `age1pqc` recipient prefix) round-trip
// correctly.
export function bech32DecodeNoLimit(input: string): { hrp: string; bytes: Uint8Array } {
  if (input.length === 0) throw new Error('bech32: empty string');
  const hasLower = input !== input.toUpperCase();
  const hasUpper = input !== input.toLowerCase();
  if (hasLower && hasUpper) throw new Error('bech32: mixed-case string');
  const s = input.toLowerCase();
  const sep = s.lastIndexOf('1');
  if (sep < 1) throw new Error('bech32: missing human-readable prefix');
  if (s.length - sep - 1 < 6) throw new Error('bech32: data too short for checksum');
  const hrp = s.slice(0, sep);
  for (let i = 0; i < hrp.length; i++) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error('bech32: invalid prefix character');
  }
  const words: number[] = [];
  for (let i = sep + 1; i < s.length; i++) {
    const v = BECH32_ALPHABET.indexOf(s[i]!);
    if (v === -1) throw new Error('bech32: invalid data character');
    words.push(v);
  }
  if (!checksumValid(hrp, words)) throw new Error('bech32: bad checksum');
  return { hrp, bytes: wordsToBytes(words.slice(0, words.length - 6)) };
}
