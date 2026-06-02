// Stripe-style prefixed resource IDs. The Postgres column stays UUIDv7; the
// wire form is `<prefix>_<26-char-crockford-base32>`. This module is the
// only place that knows the byte-level encoding — everything else (Zod
// schemas, route handlers, SDK types) consumes the helpers below.
//
// We intentionally do NOT bind the helpers to a closed prefix enum here: the
// SDK is published as a versioned dependency and adding a new resource type
// (e.g. `topup_*`) must not require an SDK bump just to validate the wire.
// The helpers therefore take the prefix as a generic string parameter; the
// per-resource Zod schemas in `./zod-schemas.ts` are the place to enumerate
// the known prefixes for validation purposes.

import { decodeBytes, encodeBytes } from './crockford-base32';

/**
 * Branded string type — `${prefix}_<26-base32-chars>`. The phantom `__brand`
 * field gives TypeScript a way to refuse a bare string at API boundaries
 * (`function fn(id: PrefixedId<'poe'>)`) while staying ABI-compatible with
 * `string` on the wire and in JSON serialisation.
 */
export type PrefixedId<P extends string> = `${P}_${string}` & { readonly __brand: P };

// 32-char hex UUID without separators is what the encoder converts to bytes.
const UUID_RE_BYTES = /^[0-9a-f]{32}$/;

function uuidStringToBytes(uuid: string): Uint8Array {
  // Accept canonical 8-4-4-4-12 hyphenated form (case-insensitive) only —
  // this is what every UUIDv4/v7 library produces and what Postgres returns
  // for the UUIDv7 columns. Anything else (no hyphens, wrong width, non-hex)
  // is rejected.
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!UUID_RE_BYTES.test(hex) || uuid.replace(/[^-]/g, '').length !== 4) {
    throw new Error(`prefixed-id: not a canonical hyphenated UUID: ${JSON.stringify(uuid)}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToUuidString(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error(`prefixed-id: expected 16 decoded bytes, got ${bytes.length}`);
  }
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Encode a bare canonical UUID string (8-4-4-4-12 hyphenated) into the
 * Stripe-style wire form `${prefix}_<crockford>`.
 */
export function encodePrefixedId<P extends string>(prefix: P, uuid: string): PrefixedId<P> {
  const bytes = uuidStringToBytes(uuid);
  const encoded = encodeBytes(bytes);
  return `${prefix}_${encoded}` as PrefixedId<P>;
}

/**
 * Decode a wire-format prefixed id back to the bare canonical UUID string.
 * Throws when the prefix does not match, the body is not 26 base32 chars,
 * or the encoded payload is malformed.
 */
export function decodePrefixedId<P extends string>(prefix: P, encoded: string): string {
  if (typeof encoded !== 'string') {
    throw new Error(`prefixed-id: expected string, got ${typeof encoded}`);
  }
  const sep = encoded.indexOf('_');
  if (sep < 0) {
    throw new Error(`prefixed-id: missing prefix separator in ${JSON.stringify(encoded)}`);
  }
  const actualPrefix = encoded.slice(0, sep);
  if (actualPrefix !== prefix) {
    throw new Error(
      `prefixed-id: expected prefix ${JSON.stringify(prefix)}, got ${JSON.stringify(actualPrefix)}`,
    );
  }
  const body = encoded.slice(sep + 1);
  const bytes = decodeBytes(body);
  return bytesToUuidString(bytes);
}

/**
 * Type guard. Cheap-check: matches the prefix and the lowercase Crockford
 * length, but does NOT validate the payload bytes round-trip. Use
 * `decodePrefixedId` when a full validation is required.
 */
export function isPrefixedId<P extends string>(
  prefix: P,
  candidate: unknown,
): candidate is PrefixedId<P> {
  if (typeof candidate !== 'string') return false;
  if (!candidate.startsWith(`${prefix}_`)) return false;
  const body = candidate.slice(prefix.length + 1);
  if (body.length !== 26) return false;
  // Strict Crockford alphabet — no I, L, O, U; lowercase only on the wire.
  return /^[0-9a-hjkmnp-tv-z]{26}$/.test(body);
}
