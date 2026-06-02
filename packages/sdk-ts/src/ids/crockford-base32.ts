// Crockford Base32 codec for 16-byte UUID payloads (yielding 26-char strings).
//
// Alphabet per https://www.crockford.com/base32.html — `0123456789ABCDEFGHJKMNPQRSTVWXYZ`
// (32 symbols; the letters I, L, O, U are intentionally excluded for visual
// disambiguation against digits and to avoid accidental profanity in
// generated identifiers).
//
// Encoding: 16 raw bytes (128 bits) packs into exactly 26 base32 symbols
// (130 bits with 2 trailing zero-padding bits we drop on encode and
// reconstruct on decode). No `=` padding character is emitted — UUID payloads
// are fixed-width.
//
// Decoding: case-insensitive (per Crockford spec); we also tolerate the
// disambiguation map I/L → 1, O → 0. The encoded length MUST be 26 chars;
// rejection is explicit (callers downstream feed the bytes back into a UUIDv7
// validator anyway, so we surface the length problem at the codec boundary).

const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

// 256-entry decode table indexed by lowercased ASCII char code. -1 = invalid.
// We populate it once at module load.
const DECODE_TABLE: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    const ch = ALPHABET.charCodeAt(i);
    table[ch] = i;
    // Uppercase variant (Crockford accepts case-insensitive input).
    const upper = String.fromCharCode(ch).toUpperCase().charCodeAt(0);
    table[upper] = i;
  }
  // Crockford disambiguation: I, L → 1; O → 0; U is reserved (always invalid).
  table['I'.charCodeAt(0)] = 1;
  table['i'.charCodeAt(0)] = 1;
  table['L'.charCodeAt(0)] = 1;
  table['l'.charCodeAt(0)] = 1;
  table['O'.charCodeAt(0)] = 0;
  table['o'.charCodeAt(0)] = 0;
  return table;
})();

export const CROCKFORD_ENCODED_LENGTH_FOR_UUID = 26;

/**
 * Encode `bytes.length` raw bytes as a lowercase Crockford base32 string.
 * Output length is `ceil(bytes.length * 8 / 5)` — no `=` padding character.
 * For 16-byte UUIDs this produces 26 chars; for 32-byte API-key secrets it
 * produces 52 chars (256 bits of entropy, matching the Stripe / OpenAI /
 * Anthropic secret-key entropy class).
 */
export function encodeBytesVariableLength(bytes: Uint8Array): string {
  let bits = 0;
  let bitCount = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    bits = (bits << 8) | bytes[i]!;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      const idx = (bits >>> bitCount) & 0x1f;
      out += ALPHABET[idx];
    }
  }
  if (bitCount > 0) {
    const idx = (bits << (5 - bitCount)) & 0x1f;
    out += ALPHABET[idx];
  }
  return out;
}

/**
 * Encode 16 raw bytes (a UUID payload) as a 26-char lowercase Crockford
 * base32 string. Throws if the input is not exactly 16 bytes.
 */
export function encodeBytes(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error(`crockford-base32: expected 16 bytes, got ${bytes.length}`);
  }
  // 16 bytes × 8 = 128 bits → 26 × 5 = 130 bits; we pad the input with 2 zero
  // bits on the right, which simply means we treat byte[15] as occupying the
  // top 8 bits of a 10-bit window for the final two symbols.
  return encodeBytesVariableLength(bytes);
}

/**
 * Decode a 26-char Crockford base32 string back to 16 raw bytes.
 * Case-insensitive; accepts the I/L → 1, O → 0 disambiguation mappings.
 * Throws on wrong length, invalid characters, or non-zero pad bits.
 */
export function decodeBytes(encoded: string): Uint8Array {
  if (encoded.length !== CROCKFORD_ENCODED_LENGTH_FOR_UUID) {
    throw new Error(
      `crockford-base32: expected ${CROCKFORD_ENCODED_LENGTH_FOR_UUID}-char input, got ${encoded.length}`,
    );
  }
  const out = new Uint8Array(16);
  let bits = 0;
  let bitCount = 0;
  let outIdx = 0;
  for (let i = 0; i < encoded.length; i++) {
    const code = encoded.charCodeAt(i);
    const value = code < 128 ? DECODE_TABLE[code]! : -1;
    if (value < 0) {
      throw new Error(
        `crockford-base32: invalid character ${JSON.stringify(encoded[i])} at index ${i}`,
      );
    }
    bits = (bits << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      out[outIdx++] = (bits >>> bitCount) & 0xff;
    }
  }
  // After 26 symbols × 5 = 130 bits consumed and 16 bytes × 8 = 128 bits
  // emitted, there should be exactly 2 trailing zero pad bits. Anything else
  // means the input wasn't produced by our encoder (or was tampered with).
  if (bitCount !== 2 || (bits & 0x3) !== 0) {
    throw new Error('crockford-base32: non-zero pad bits at end of input');
  }
  return out;
}
