// Lower-case hex → bytes decoder. Caller is responsible for normalising
// case + stripping any 0x prefix; the input must match /^[0-9a-f]*$/ with
// even length. The decoder allocates exactly one fresh Uint8Array and
// returns it as-is so callers downstream can rely on reference identity
// (e.g. caller-owns-zeroize discipline for raw-seed import: the caller can
// wipe the exact buffer this function returned).
export function hexToBytes(hex: string): Uint8Array {
  if ((hex.length & 1) !== 0) {
    throw new Error(`hexToBytes: input length ${hex.length} is not even`);
  }
  const out = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < out.length; i++) {
    const hi = charToNibble(hex.charCodeAt(i * 2));
    const lo = charToNibble(hex.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) {
      throw new Error(`hexToBytes: non-hex character at offset ${i * 2}`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function charToNibble(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}
