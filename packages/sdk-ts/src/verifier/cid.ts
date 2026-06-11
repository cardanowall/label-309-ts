// Offline CID decoding for the content-address binding of fetched bytes.
//
// Both fetch schemes are content-addressed, so fetched bytes CAN be verified
// against the URI itself — independently of whichever gateway served them.
// The binding check decides ATTRIBUTION, and attribution decides what a
// mismatch means: attributable bytes failing a record commitment condemn the
// record (URI_INTEGRITY_MISMATCH); unattributable bytes indict only the
// serving provider (URI_PROVIDER_INTEGRITY_MISMATCH).
//
// This implementation verifies the binding for the raw-codec CIDv1 case: the
// multihash is computed directly over the content bytes, so a plain hash
// recompute proves the gateway served exactly what the CID addresses. The
// other forms need block-level verification this SDK does not implement —
// DAG CIDs (dag-pb / dag-cbor, including every CIDv0) commit to encoded
// blocks rather than the file bytes a path gateway returns, and `ar://`
// needs the Arweave data_root chunk tree or the ANS-104 deep-hash — so
// fetched bytes under those forms stay UNVERIFIED and their mismatches are
// routed through the provider code, never URI_INTEGRITY_MISMATCH.
//
// The accepted multibase / multicodec / multihash sets mirror the normative
// CID profile (already enforced by the structural validator); anything
// outside it simply yields `unsupported` here.

import { blake2b256, sha256 } from '@cardanowall/crypto-core/hash';

const CODEC_RAW = 0x55;
const MULTIHASH_SHA2_256 = 0x12;
const MULTIHASH_BLAKE2B_256 = 0xb220;

export interface ParsedCid {
  readonly version: 0 | 1;
  readonly codec: number;
  readonly multihashCode: number;
  readonly digest: Uint8Array;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(BASE58_ALPHABET, (c, i) => [c, i] as const),
);

function base58Decode(input: string): Uint8Array | null {
  if (input.length === 0) return null;
  const bytes: number[] = [0];
  for (const ch of input) {
    const value = BASE58_INDEX.get(ch);
    if (value === undefined) return null;
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i]! * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1' characters encode leading zero bytes.
  for (const ch of input) {
    if (ch !== '1') break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const BASE32_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(BASE32_ALPHABET, (c, i) => [c, i] as const),
);

function base32Decode(input: string): Uint8Array | null {
  let bits = 0;
  let acc = 0;
  const out: number[] = [];
  for (const ch of input) {
    const value = BASE32_INDEX.get(ch);
    if (value === undefined) return null;
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  // Trailing bits must be zero padding only.
  if ((acc & ((1 << bits) - 1)) !== 0) return null;
  return new Uint8Array(out);
}

function base16Decode(input: string): Uint8Array | null {
  if (input.length % 2 !== 0 || !/^[0-9a-f]*$/.test(input)) return null;
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(input.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function readVarint(bytes: Uint8Array, pos: number): { value: number; next: number } | null {
  let value = 0;
  let shift = 0;
  let p = pos;
  for (;;) {
    if (p >= bytes.length || shift > 28) return null;
    const b = bytes[p]!;
    value |= (b & 0x7f) << shift;
    p += 1;
    if ((b & 0x80) === 0) return { value: value >>> 0, next: p };
    shift += 7;
  }
}

/**
 * Decode the authority component of an `ipfs://` URI into its CID fields.
 * Returns `null` for anything outside the profile's multibase set or for
 * undecodable input — callers treat that exactly like an unsupported binding.
 */
export function parseCid(cid: string): ParsedCid | null {
  if (cid.length === 0) return null;

  // CIDv0: fixed base58btc "Qm…" shape, an implied dag-pb + sha2-256 multihash.
  if (cid.startsWith('Qm') && cid.length === 46) {
    const decoded = base58Decode(cid);
    if (decoded === null || decoded.length !== 34) return null;
    if (decoded[0] !== MULTIHASH_SHA2_256 || decoded[1] !== 32) return null;
    return {
      version: 0,
      codec: 0x70,
      multihashCode: MULTIHASH_SHA2_256,
      digest: decoded.slice(2),
    };
  }

  const prefix = cid[0]!;
  const body = cid.slice(1);
  let decoded: Uint8Array | null;
  switch (prefix) {
    case 'b':
      decoded = base32Decode(body);
      break;
    case 'B':
      decoded = base32Decode(body.toLowerCase());
      break;
    case 'f':
      decoded = base16Decode(body);
      break;
    case 'F':
      decoded = base16Decode(body.toLowerCase());
      break;
    case 'z':
      decoded = base58Decode(body);
      break;
    default:
      return null;
  }
  if (decoded === null) return null;

  const version = readVarint(decoded, 0);
  if (version === null || version.value !== 1) return null;
  const codec = readVarint(decoded, version.next);
  if (codec === null) return null;
  const mhCode = readVarint(decoded, codec.next);
  if (mhCode === null) return null;
  const mhLength = readVarint(decoded, mhCode.next);
  if (mhLength === null) return null;
  const digest = decoded.slice(mhLength.next);
  if (digest.length !== mhLength.value) return null;
  return { version: 1, codec: codec.value, multihashCode: mhCode.value, digest };
}

export type CidBindingOutcome = 'verified' | 'failed' | 'unsupported';

/**
 * The minimum binding check: for a raw-codec CIDv1 with no path component,
 * recompute the multihash directly over the fetched bytes and compare it to
 * the CID's digest. Everything else — CIDv0, DAG codecs, a path component
 * (which navigates a DAG the raw recompute cannot reproduce), an
 * out-of-profile multihash — is `unsupported`: the bytes stay unattributed
 * and a mismatch indicts the provider, never the record.
 */
export function verifyIpfsCidBinding(args: {
  readonly cid: string;
  readonly path: string; // '' when the URI carries no path component
  readonly bytes: Uint8Array;
}): CidBindingOutcome {
  if (args.path !== '') return 'unsupported';
  const parsed = parseCid(args.cid);
  if (parsed === null || parsed.version !== 1 || parsed.codec !== CODEC_RAW) {
    return 'unsupported';
  }
  let computed: Uint8Array;
  if (parsed.multihashCode === MULTIHASH_SHA2_256) {
    computed = sha256(args.bytes);
  } else if (parsed.multihashCode === MULTIHASH_BLAKE2B_256) {
    computed = blake2b256(args.bytes);
  } else {
    return 'unsupported';
  }
  if (computed.length !== parsed.digest.length) return 'failed';
  for (let i = 0; i < computed.length; i++) {
    if (computed[i] !== parsed.digest[i]) return 'failed';
  }
  return 'verified';
}
