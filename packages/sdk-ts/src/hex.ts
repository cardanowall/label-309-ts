// Lowercase, no-`0x`-prefix hex encoder shared across the SDK. Single
// implementation so the verifier, the wire serialiser, and the publish client
// all emit byte-identical hex (the Python parity twin and the cross-language
// fixtures depend on this exact form).

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
