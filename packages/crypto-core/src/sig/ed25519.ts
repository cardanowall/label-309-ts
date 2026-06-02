import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

ed.hashes.sha512 = sha512;

// Ed25519 group order L (= 2^252 + 27742317777372353535851937790883648493).
const L = ed.Point.CURVE().n;

export interface SignEd25519Opts {
  readonly seed: Uint8Array;
  readonly message: Uint8Array;
}

export interface VerifyEd25519Opts {
  readonly publicKey: Uint8Array;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
}

export interface GetPublicKeyEd25519Opts {
  readonly seed: Uint8Array;
}

export function signEd25519(opts: SignEd25519Opts): Uint8Array {
  return ed.sign(opts.message, opts.seed);
}

// Little-endian 32-byte scalar → bigint.
function leBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i]!);
  }
  return value;
}

// Strict (non-cofactored) Ed25519 verification per RFC 8032 §5.1.7, matching
// libsodium/PyNaCl `crypto_sign_verify_detached` and ed25519-dalek
// `verify_strict`. The cofactor-less check rejects every small-order /
// torsion-component edge case in the C2SP/CCTV corpus, which noble's
// `{ zip215: false }` mode does NOT (it remains cofactored: it checks
// `[8]([S]B - [k]A - R) == 0`, accepting torsion components).
//
// The verification equation is the unscaled `[S]B == R + [k]A`, rewritten as
// `[S]B - [k]A - R == identity`. We reject S >= L (non-canonical scalar) and
// any small-order A or R up front, so a torsion component can never be smuggled
// through the cofactor multiplication the cofactored variant performs.
export function verifyEd25519(opts: VerifyEd25519Opts): boolean {
  const { signature, message, publicKey } = opts;
  if (signature.length !== 64 || publicKey.length !== 32) return false;

  // S = LE(sig[32..64]); reject if not a canonical scalar (S >= L).
  const S = leBytesToBigInt(signature.subarray(32, 64));
  if (S >= L) return false;

  // Decode A (public key) and R (sig[0..32]) with the canonical (non-zip215)
  // point encoding; a non-canonical encoding throws and rejects.
  let A: ed.Point;
  let R: ed.Point;
  try {
    A = ed.Point.fromBytes(publicKey);
    R = ed.Point.fromBytes(signature.subarray(0, 32));
  } catch {
    return false;
  }

  // Reject small-order (cofactor-torsion) A or R: this is exactly the strictness
  // that distinguishes verify_strict from the cofactored check.
  if (A.isSmallOrder() || R.isSmallOrder()) return false;

  // k = SHA-512(R || A || M) reduced mod L.
  const k =
    leBytesToBigInt(ed.hash(concatBytes(signature.subarray(0, 32), publicKey, message))) % L;

  // Accept iff [S]B - [k]A - R == identity. `multiplyUnsafe` returns the
  // identity for a 0 scalar, but guard explicitly to avoid relying on that.
  const sB = S === 0n ? ed.Point.ZERO : ed.Point.BASE.multiplyUnsafe(S);
  const kA = k === 0n ? ed.Point.ZERO : A.multiplyUnsafe(k);
  return sB.subtract(kA).subtract(R).is0();
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function getPublicKeyEd25519(opts: GetPublicKeyEd25519Opts): Uint8Array {
  return ed.getPublicKey(opts.seed);
}
