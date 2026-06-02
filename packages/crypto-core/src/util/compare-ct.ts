// Isomorphic constant-time byte-equality. crypto-core is browser-safe by
// design, so we cannot import `node:crypto.timingSafeEqual` — webpack rejects
// the `node:` scheme in the browser bundle. A pure-JS XOR loop is constant-time
// for equal-length inputs; length mismatch is a deliberate early-return (the
// API surface itself leaks length, same as node's timingSafeEqual which throws).
export function compareCt(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  // Lengths are equal and `i` stays in-bounds, so both indexes are always
  // defined — no nullish guard is needed (and one would read as a guard for
  // an impossible case).
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
