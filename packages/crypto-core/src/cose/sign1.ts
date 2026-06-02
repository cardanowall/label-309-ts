import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '../cbor/canonical';
import { CanonicalCborError } from '../cbor/errors';
import { blake2b224 } from '../hash/blake2b-256';
import { signEd25519, verifyEd25519 } from '../sig/ed25519';
import { compareCt } from '../util/compare-ct';

import { CoseVerifyError, type CoseVerifyResult } from './errors';

export type CoseHeader = Map<number | string, unknown>;

// CIP-309 v1 domain separator embedded as a prefix on `Sig_structure[3]`
// (`to_sign`). The separator is
// NOT placed in `Sig_structure[2]` (`external_aad`) because CIP-30 `signData`
// — the only realistic wallet-signing path on Cardano — explicitly forbids a
// non-empty `external_aad`. Pinning the prefix into the payload preserves the
// anti-replay property while keeping wallet-produced signatures byte-identical
// to verifier-side recomputation.
export const CARDANO_POE_SIG_DOMAIN_PREFIX = 'cardano-poe-record-sig-v1' as const;
// Composer path-2 wallet flow consumes the prefix bytes directly
// to assemble `toSign = prefix || canonical_cbor(record_body)` BEFORE calling
// `walletSignData` (the wallet's `signData()` receives this concatenation as
// its `payload` argument verbatim per CIP-30). The bytes constant is exported
// so a composer can build the input without re-encoding the prefix at every
// call site.
export const CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES = new TextEncoder().encode(
  CARDANO_POE_SIG_DOMAIN_PREFIX,
);

// Fail-fast: the prefix length is byte-pinned at 25 UTF-8 bytes. A different
// runtime encoding would silently break round-tripping
// against the reference vectors.
if (CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length !== 25) {
  throw new Error(
    `cardano-poe-record-sig-v1 prefix must encode to exactly 25 UTF-8 bytes, got ${CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length}`,
  );
}

const EMPTY_BYTES = new Uint8Array(0);

export interface CoseSign1Decoded {
  readonly protectedHeader: CoseHeader;
  // preserved for Sig_structure reconstruction — never re-encode the decoded header map (RFC 9052 §4.4)
  readonly protectedBytes: Uint8Array;
  readonly unprotectedHeader: CoseHeader;
  readonly payload: Uint8Array | null;
  readonly signature: Uint8Array;
}

export interface BuildSigStructureArgs {
  readonly context: 'Signature1';
  readonly bodyProtectedBytes: Uint8Array;
  readonly externalAad: Uint8Array;
  readonly payload: Uint8Array;
}

// Raw RFC 9052 §4.4 Sig_structure builder. General-purpose: callers control
// `external_aad` and `payload` exactly. For CIP-309 record signing use
// `buildCip309SigStructure` instead — it enforces the CIP-309 record-signature invariants.
export function buildSigStructure(args: BuildSigStructureArgs): Uint8Array {
  return encodeCanonicalCbor([
    args.context,
    args.bodyProtectedBytes,
    args.externalAad,
    args.payload,
  ] as readonly CanonicalCborValue[]);
}

export interface BuildCip309SigStructureArgs {
  readonly bodyProtectedBytes: Uint8Array;
  // Canonical CBOR of the record body with `sigs` removed.
  readonly recordBodyCbor: Uint8Array;
}

// CIP-309 v1 specialisation of `Sig_structure` (RFC 9052 §4.4 base structure):
//   to_sign       = utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_minus_sigs)
//   Sig_structure = [ "Signature1", body_protected, h'' (empty), to_sign ]
// Always forces `external_aad = h''` (empty bstr) — the CIP-30 wallet path
// cannot carry a non-empty `external_aad`, so the domain separator lives in
// `Sig_structure[3]` rather than `Sig_structure[2]`.
export function buildCip309SigStructure(args: BuildCip309SigStructureArgs): Uint8Array {
  const toSign = new Uint8Array(
    CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + args.recordBodyCbor.length,
  );
  toSign.set(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES, 0);
  toSign.set(args.recordBodyCbor, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
  return buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: args.bodyProtectedBytes,
    externalAad: EMPTY_BYTES,
    payload: toSign,
  });
}

export interface EncodeCoseSign1Args {
  readonly protectedHeader: CoseHeader;
  readonly unprotectedHeader: CoseHeader;
  readonly payload: Uint8Array | null;
  readonly signature: Uint8Array;
}

export function encodeCoseSign1(args: EncodeCoseSign1Args): Uint8Array {
  const protectedBytes =
    args.protectedHeader.size === 0
      ? EMPTY_BYTES
      : encodeCanonicalCbor(args.protectedHeader as CanonicalCborValue);
  return encodeCanonicalCbor([
    protectedBytes,
    args.unprotectedHeader as CanonicalCborValue,
    args.payload,
    args.signature,
  ] as readonly CanonicalCborValue[]);
}

// cbor2's decoder returns Map for integer-keyed maps but plain Object for empty
// or string-keyed maps; normalise both representations to Map.
function asCoseHeader(value: unknown): CoseHeader | null {
  if (value instanceof Map) return value as CoseHeader;
  if (value !== null && typeof value === 'object' && (value as object).constructor === Object) {
    return new Map(Object.entries(value as Record<string, unknown>));
  }
  return null;
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1Decoded {
  let arr: unknown;
  try {
    arr = decodeCanonicalCbor(bytes);
  } catch (cause) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'cose decode failed', { cause });
  }
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'expected 4-element array');
  }
  const [protectedBytesRaw, unprotectedRaw, payloadRaw, signatureRaw] = arr;
  if (!(protectedBytesRaw instanceof Uint8Array)) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'protected_bytes must be bytes');
  }
  const unprotectedHeader = asCoseHeader(unprotectedRaw);
  if (unprotectedHeader === null) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'unprotected header must be map');
  }
  if (payloadRaw !== null && !(payloadRaw instanceof Uint8Array)) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'payload must be bytes or null');
  }
  if (!(signatureRaw instanceof Uint8Array) || signatureRaw.length !== 64) {
    throw new CoseVerifyError('MALFORMED_SIG_COSE', 'signature must be 64 bytes');
  }
  let protectedHeader: CoseHeader;
  if (protectedBytesRaw.length === 0) {
    protectedHeader = new Map();
  } else {
    let decodedProtected: unknown;
    try {
      decodedProtected = decodeCanonicalCbor(protectedBytesRaw);
    } catch (cause) {
      throw new CoseVerifyError('MALFORMED_SIG_COSE', 'protected header decode failed', { cause });
    }
    const ph = asCoseHeader(decodedProtected);
    if (ph === null) {
      throw new CoseVerifyError('MALFORMED_SIG_COSE', 'protected header must decode to map');
    }
    // Empty protected header MUST encode as the single byte 0x40 (zero-length bstr),
    // not 0x41 0xA0 (a 1-byte bstr containing an empty CBOR map). RFC 9052 §3 +
    // CIP-309 canonical-CBOR mandate.
    if (ph.size === 0) {
      throw new CoseVerifyError(
        'MALFORMED_SIG_COSE',
        'empty protected header must encode as 0x40 (zero-length bstr), not as an empty map',
      );
    }
    protectedHeader = ph;
  }
  return {
    protectedHeader,
    protectedBytes: protectedBytesRaw,
    unprotectedHeader,
    payload: payloadRaw,
    signature: signatureRaw,
  };
}

export type CoseSign1BuildErrorCode = 'SIGNER_NOT_PROVIDED' | 'SIGNER_AND_SEED_BOTH_PROVIDED';

export class CoseSign1BuildError extends Error {
  readonly code: CoseSign1BuildErrorCode;

  constructor(code: CoseSign1BuildErrorCode, message: string) {
    super(message);
    this.name = 'CoseSign1BuildError';
    this.code = code;
  }
}

export interface CoseSign1Cip309BuildArgs {
  readonly protectedHeader: CoseHeader;
  readonly unprotectedHeader: CoseHeader;
  // Canonical CBOR of the record body with `sigs` removed. The
  // builder prepends the 25-byte UTF-8 domain prefix `cardano-poe-record-sig-v1`
  // internally — callers MUST NOT pre-concatenate it.
  readonly recordBodyCbor: Uint8Array;
  // EITHER the raw 32-byte Ed25519 seed (used by KAT tests, Python parity, and
  // the off-host signing helper) OR an injected signer closure that signs the
  // assembled Sig_structure bytes (composer-side use — keeps the private key
  // inside the unlock-store closure so it never escapes scope).
  // Exactly one of the two MUST be provided; mutual exclusion enforced at
  // runtime via CoseSign1BuildError.
  readonly signerSecretKey?: Uint8Array;
  readonly signer?: (sigStructureBytes: Uint8Array) => Uint8Array;
}

// CIP-309 v1 record-signature builder:
//   1. compute `to_sign = utf8("cardano-poe-record-sig-v1") || recordBodyCbor`
//   2. Sig_structure = [ "Signature1", bodyProtected, h'', to_sign ]
//   3. Ed25519-sign Sig_structure (via seed OR injected closure)
//   4. emit COSE_Sign1 with payload = CBOR null (detached signature, mandatory)
export function coseSign1Cip309Build(args: CoseSign1Cip309BuildArgs): Uint8Array {
  if (args.signerSecretKey === undefined && args.signer === undefined) {
    throw new CoseSign1BuildError(
      'SIGNER_NOT_PROVIDED',
      'coseSign1Cip309Build requires either signerSecretKey or signer',
    );
  }
  if (args.signerSecretKey !== undefined && args.signer !== undefined) {
    throw new CoseSign1BuildError(
      'SIGNER_AND_SEED_BOTH_PROVIDED',
      'coseSign1Cip309Build accepts signerSecretKey XOR signer (not both)',
    );
  }
  const protectedBytes =
    args.protectedHeader.size === 0
      ? EMPTY_BYTES
      : encodeCanonicalCbor(args.protectedHeader as CanonicalCborValue);
  const sigStructureBytes = buildCip309SigStructure({
    bodyProtectedBytes: protectedBytes,
    recordBodyCbor: args.recordBodyCbor,
  });
  let signature: Uint8Array;
  if (args.signer !== undefined) {
    signature = args.signer(sigStructureBytes);
    if (!(signature instanceof Uint8Array) || signature.length !== 64) {
      throw new CoseSign1BuildError(
        'SIGNER_NOT_PROVIDED',
        `injected signer must return a 64-byte Uint8Array; got ${signature instanceof Uint8Array ? `${signature.length}-byte Uint8Array` : typeof signature}`,
      );
    }
  } else {
    signature = signEd25519({ seed: args.signerSecretKey!, message: sigStructureBytes });
  }
  return encodeCoseSign1({
    protectedHeader: args.protectedHeader,
    unprotectedHeader: args.unprotectedHeader,
    payload: null,
    signature,
  });
}

export interface CoseSign1Cip309VerifyArgs {
  readonly message: Uint8Array;
  // Canonical CBOR of the record body with `sigs` removed (verifier-recomputed;
  // the 25-byte UTF-8 prefix is prepended internally — callers
  // MUST NOT pre-concatenate it).
  readonly detachedRecordBodyCbor: Uint8Array;
  // Optional out-of-band signer key (path-2 wallet path resolves the key from
  // `sigs[i].cose_key`). Path-1 records carry the 32-byte raw Ed25519 pubkey
  // in the protected header at label 4 (`kid`) and need no out-of-band hint.
  readonly expectedSignerKey?: Uint8Array;
}

// CIP-309 v1 record-signature verifier:
//   - Decode COSE_Sign1
//   - Reject COSE_Sign1[2] != CBOR null (attached payload — including h'') as
//     MALFORMED_SIG_COSE_SIGN1
//   - Recompute to_sign = utf8("cardano-poe-record-sig-v1") || detachedRecordBodyCbor
//   - Sig_structure = [ "Signature1", protectedBytes, h'', to_sign ]
//   - Strict Ed25519 verify (RFC 8032 §5.1.7 — `zip215: false` per ed25519.ts)
//
// The verifier does NOT accept an `externalAad` argument: CIP-309 v1 pins
// `external_aad = h''` and any deviation would either silently weaken the
// domain separator or quietly accept malformed records. If a future CIP
// revision re-enables external_aad, this helper takes a v-bump.
export function coseSign1Cip309Verify(args: CoseSign1Cip309VerifyArgs): CoseVerifyResult {
  let decoded: CoseSign1Decoded;
  try {
    decoded = decodeCoseSign1(args.message);
  } catch (e) {
    if (e instanceof CoseVerifyError) {
      return { ok: false, error: { code: e.code, message: 'errors.cose.malformed' } };
    }
    if (e instanceof CanonicalCborError) {
      return {
        ok: false,
        error: { code: 'MALFORMED_SIG_COSE', message: 'errors.cose.malformed_cbor' },
      };
    }
    throw e;
  }
  // CIP-309 v1 mandate: COSE_Sign1[2] (payload field) MUST be CBOR `null` (0xF6).
  // Any non-null payload — including a zero-length byte string `h''` — MUST
  // be rejected as MALFORMED_SIG_COSE_SIGN1.
  if (decoded.payload !== null) {
    return {
      ok: false,
      error: {
        code: 'MALFORMED_SIG_COSE_SIGN1',
        message: 'errors.cose.attached_payload_forbidden',
      },
    };
  }
  const alg = decoded.protectedHeader.get(1);
  if (typeof alg !== 'number' || alg !== -8) {
    return {
      ok: false,
      error: { code: 'UNSUPPORTED_SIG_ALG', message: 'errors.cose.unsupported_alg' },
    };
  }
  const kidRaw = decoded.protectedHeader.get(4);
  let signerKey: Uint8Array | undefined;
  if (kidRaw instanceof Uint8Array && kidRaw.length === 32) {
    signerKey = kidRaw;
  } else if (args.expectedSignerKey instanceof Uint8Array && args.expectedSignerKey.length === 32) {
    signerKey = args.expectedSignerKey;
  }
  if (signerKey === undefined) {
    return {
      ok: false,
      error: { code: 'KID_UNRESOLVED', message: 'errors.cose.kid_unresolved' },
    };
  }
  // When both a protected-header kid AND an expectedSignerKey are provided,
  // require they agree (constant-time). A protected kid that disagrees with
  // the caller's out-of-band binding is a misuse, not a transient mismatch.
  if (
    kidRaw instanceof Uint8Array &&
    kidRaw.length === 32 &&
    args.expectedSignerKey instanceof Uint8Array &&
    args.expectedSignerKey.length === 32 &&
    !compareCt(kidRaw, args.expectedSignerKey)
  ) {
    return {
      ok: false,
      error: { code: 'KID_UNRESOLVED', message: 'errors.cose.kid_mismatch' },
    };
  }
  // CIP-8 `hashed = true` mode (the wallet-signed path-2 variant). The unprotected
  // header carries the literal text key `"hashed"` with boolean value `true`
  // (text-keyed CBOR maps decode to `Map<string, unknown>` via cbor2). When
  // set, both producer and verifier build `Sig_structure[3] = Blake2b-224(to_sign)`
  // (28-byte digest of the FULL `to_sign` payload including the 25-byte
  // domain prefix). When absent or false, the standard non-hashed path
  // applies unchanged.
  const hashedFlag = decoded.unprotectedHeader.get('hashed');
  let sigStructureBytes: Uint8Array;
  if (hashedFlag === true) {
    const toSign = new Uint8Array(
      CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + args.detachedRecordBodyCbor.length,
    );
    toSign.set(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES, 0);
    toSign.set(args.detachedRecordBodyCbor, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
    const hashedPayload = blake2b224(toSign);
    sigStructureBytes = buildSigStructure({
      context: 'Signature1',
      bodyProtectedBytes: decoded.protectedBytes,
      externalAad: EMPTY_BYTES,
      payload: hashedPayload,
    });
  } else {
    sigStructureBytes = buildCip309SigStructure({
      bodyProtectedBytes: decoded.protectedBytes,
      recordBodyCbor: args.detachedRecordBodyCbor,
    });
  }
  const valid = verifyEd25519({
    publicKey: signerKey,
    message: sigStructureBytes,
    signature: decoded.signature,
  });
  if (!valid) {
    return {
      ok: false,
      error: { code: 'SIGNATURE_INVALID', message: 'errors.cose.signature_invalid' },
    };
  }
  return { ok: true, signerKey, alg };
}
