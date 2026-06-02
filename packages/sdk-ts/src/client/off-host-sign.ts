// CIP-309 v1 off-host signing helper. The signing key never leaves the user
// device — this module touches only the public-data inputs (record bytes +
// pubkey) and the public-data output (the 64-byte Ed25519 signature). The
// integrator's signer callback owns the private key material.
//
// Wire-format invariants enforced by this module:
//   - Sig_structure carries the 25-byte UTF-8 domain prefix
//     `cardano-poe-record-sig-v1` with `external_aad = h''` (RFC 9052 §4.4
//     under the CIP-30 compatibility constraint).
//   - COSE_Sign1 (RFC 9052 §4.2) has a detached payload: COSE_Sign1[2] = CBOR
//     null. CIP-8 `hashed = true` mode places the literal text key
//     `"hashed"` in the unprotected header.
//   - Path-1 `kid-as-public-key` convention: 32-byte raw Ed25519 pubkey in
//     protected header label 4; path-1 / path-2 are mutually exclusive on
//     the wire.
//   - chunked-bytes-array: per-chunk size in [1, 64].
//
// Use cases (the four integration shapes this surface is intended for):
//   1. AWS KMS `Sign` over the returned Sig_structure bytes — wrap KMS as
//      `(bytes) => Promise<signature>`.
//   2. Google Cloud HSM — same `(bytes) => Promise<signature>` shape.
//   3. YubiHSM — local hardware-backed signer; same shape via the YubiHSM SDK.
//   4. Air-gapped offline signer — transport the Sig_structure bytes via QR /
//      USB / sneakernet to the offline workstation; transport the 64-byte
//      Ed25519 signature back.
//
// This module is PATH-1 ONLY. The CIP-30 wallet path (path-2) is handled
// separately — adding a `cose_key` sidecar here would violate the path-1 /
// path-2 mutual-exclusion rule (SIG_ENTRY_KID_COSE_KEY_CONFLICT).
//
// Hashed-mode (`prepareSigStructureHashed` / `assembleCoseSign1Hashed`) is
// DISCOURAGED for software off-host signers (AWS KMS, GCP HSM, YubiHSM —
// each accepts arbitrary-length input) — use the non-hashed mode instead.
// Hashed mode exists only for hardware co-signers with limited screen /
// buffer. The verifier MUST recognise the `"hashed": true` unprotected-header
// flag and substitute `Sig_structure[3]` with `Blake2b-224(to_sign)` before
// strict Ed25519 verification.
//
// Privacy contract: the SDK never sees, stores, logs, or transmits any byte
// string that contains the integrator's Ed25519 private signing key. The
// integrator's signer handles the seed; this module touches only the 32-byte
// public key and the 64-byte signature (both public data).
//
// The Python SDK carries the same builder (snake_case function names);
// byte-identical outputs across the two are enforced by a shared
// known-answer-test corpus.

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import {
  CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES,
  buildCip309SigStructure,
  buildSigStructure,
  encodeCoseSign1,
  type CoseHeader,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import {
  chunkBytes,
  encodeRecordBodyForSigning,
  type ChunkedBytesArray,
  type PoeRecord,
  type SigEntry,
} from '@cardanowall/poe-standard';

const EMPTY_BYTES = new Uint8Array(0);
const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_SIGNATURE_LENGTH = 64;

export type OffHostSignErrorCode = 'INVALID_PUBKEY_LENGTH' | 'INVALID_SIGNATURE_LENGTH';

export class OffHostSignError extends Error {
  readonly code: OffHostSignErrorCode;

  constructor(code: OffHostSignErrorCode, message: string) {
    super(message);
    this.name = 'OffHostSignError';
    this.code = code;
  }
}

export interface PrepareSigStructureArgs {
  readonly record: PoeRecord;
  readonly signerPubkey: Uint8Array;
}

export interface PrepareSigStructureResult {
  readonly sigStructureBytes: Uint8Array;
  readonly protectedHeaderBytes: Uint8Array;
}

export interface PrepareSigStructureHashedResult extends PrepareSigStructureResult {
  readonly toSignHashBytes: Uint8Array;
}

export interface AssembleCoseSign1Args {
  readonly record: PoeRecord;
  readonly signerPubkey: Uint8Array;
  readonly signature: Uint8Array;
}

export interface AssembleCoseSign1Result {
  readonly coseSign1Bytes: Uint8Array;
  readonly sigEntry: SigEntry;
}

// `to_sign = utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_minus_sigs)`.
// The first 25 bytes are byte-pinned to the prefix constant; bytes 25..end
// are the canonical CBOR of the record body with `sigs` removed.
export function buildToSign(record: PoeRecord): Uint8Array {
  const body = encodeRecordBodyForSigning(record);
  const out = new Uint8Array(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + body.length);
  out.set(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES, 0);
  out.set(body, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
  return out;
}

// Path-1 protected header canonical CBOR for `{1: -8, 4: <signerPubkey>}`.
// Always 38 bytes: `a2 01 27 04 58 20 || <32-byte pubkey>`.
function encodePath1ProtectedHeader(signerPubkey: Uint8Array): {
  protectedHeader: CoseHeader;
  protectedHeaderBytes: Uint8Array;
} {
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, signerPubkey],
  ]);
  const protectedHeaderBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
  return { protectedHeader, protectedHeaderBytes };
}

// Returns the full `Sig_structure = [ "Signature1", protected_bytes, h'', to_sign ]`
// canonical-CBOR bytes that the off-host signer feeds verbatim to Ed25519.
// `protectedHeaderBytes` is exposed so integrators can byte-compare against
// fixtures (always 38 bytes for the path-1 `{1:-8, 4:<pub>}` map).
export function prepareSigStructure(args: PrepareSigStructureArgs): PrepareSigStructureResult {
  if (args.signerPubkey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new OffHostSignError(
      'INVALID_PUBKEY_LENGTH',
      `signerPubkey must be 32 bytes (Ed25519 raw public key), got ${args.signerPubkey.length}`,
    );
  }
  const { protectedHeaderBytes } = encodePath1ProtectedHeader(args.signerPubkey);
  const recordBodyCbor = encodeRecordBodyForSigning(args.record);
  const sigStructureBytes = buildCip309SigStructure({
    bodyProtectedBytes: protectedHeaderBytes,
    recordBodyCbor,
  });
  return { sigStructureBytes, protectedHeaderBytes };
}

// Assembles `COSE_Sign1 = [ protected_bytes, unprotected_map, null, signature ]`
// (detached payload, `alg = -8`, protected `kid = signerPubkey`), chunks the
// result into the CIP-309 chunked-bytes-array shape, and emits a path-1-only
// `{cose_sign1}` `sigs[i]` entry.
export function assembleCoseSign1(args: AssembleCoseSign1Args): AssembleCoseSign1Result {
  if (args.signerPubkey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new OffHostSignError(
      'INVALID_PUBKEY_LENGTH',
      `signerPubkey must be 32 bytes (Ed25519 raw public key), got ${args.signerPubkey.length}`,
    );
  }
  if (args.signature.length !== ED25519_SIGNATURE_LENGTH) {
    throw new OffHostSignError(
      'INVALID_SIGNATURE_LENGTH',
      `signature must be 64 bytes (Ed25519 raw signature), got ${args.signature.length}`,
    );
  }
  const { protectedHeader } = encodePath1ProtectedHeader(args.signerPubkey);
  const coseSign1Bytes = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map(),
    payload: null,
    signature: args.signature,
  });
  const chunks = chunkBytes(coseSign1Bytes) as ChunkedBytesArray;
  const sigEntry: SigEntry = { cose_sign1: chunks };
  return { coseSign1Bytes, sigEntry };
}

// CIP-8 `hashed = true` companion. Substitutes `Sig_structure[3]` with
// `Blake2b-224(to_sign)`. The hash covers the ENTIRE `to_sign` payload
// (i.e. `utf8(prefix) || record_body_cbor`) — keeping the 25-byte domain
// separator inside the hash boundary preserves cross-protocol replay
// protection even in hashed mode.
//
// DISCOURAGED for software off-host signers; use only for hardware co-signers
// with screen / buffer constraints.
export function prepareSigStructureHashed(
  args: PrepareSigStructureArgs,
): PrepareSigStructureHashedResult {
  if (args.signerPubkey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new OffHostSignError(
      'INVALID_PUBKEY_LENGTH',
      `signerPubkey must be 32 bytes (Ed25519 raw public key), got ${args.signerPubkey.length}`,
    );
  }
  const { protectedHeaderBytes } = encodePath1ProtectedHeader(args.signerPubkey);
  const toSign = buildToSign(args.record);
  const toSignHashBytes = blake2b224(toSign);
  const sigStructureBytes = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: protectedHeaderBytes,
    externalAad: EMPTY_BYTES,
    payload: toSignHashBytes,
  });
  return { sigStructureBytes, protectedHeaderBytes, toSignHashBytes };
}

// Assemble hashed-mode COSE_Sign1. The unprotected header carries
// `"hashed": true` (text key), signalling to the verifier that the
// Blake2b-224 substitution applies.
export function assembleCoseSign1Hashed(args: AssembleCoseSign1Args): AssembleCoseSign1Result {
  if (args.signerPubkey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new OffHostSignError(
      'INVALID_PUBKEY_LENGTH',
      `signerPubkey must be 32 bytes (Ed25519 raw public key), got ${args.signerPubkey.length}`,
    );
  }
  if (args.signature.length !== ED25519_SIGNATURE_LENGTH) {
    throw new OffHostSignError(
      'INVALID_SIGNATURE_LENGTH',
      `signature must be 64 bytes (Ed25519 raw signature), got ${args.signature.length}`,
    );
  }
  const { protectedHeader } = encodePath1ProtectedHeader(args.signerPubkey);
  const unprotectedHeader: CoseHeader = new Map<number | string, unknown>([['hashed', true]]);
  const coseSign1Bytes = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader,
    payload: null,
    signature: args.signature,
  });
  const chunks = chunkBytes(coseSign1Bytes) as ChunkedBytesArray;
  const sigEntry: SigEntry = { cose_sign1: chunks };
  return { coseSign1Bytes, sigEntry };
}
