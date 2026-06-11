// Label 309 v1 record encoder.
//
// Produces canonical CBOR bytes per RFC 8949 §4.2.1 deterministic encoding —
// definite lengths, bytewise-lexicographically sorted map keys, no duplicate
// keys, shortest-form integers. The canonical layer
// (`@cardanowall/crypto-core/cbor`) owns those rules, so this module's job is
// only to project the typed record onto the CBOR value algebra.
//
// That projection is the identity: under the Label 309 wire shapes every
// record field already IS its CBOR value — `hashes` is a text-keyed map of
// byte-string digests, each URI is a single text string, `kem_ct` /
// `cose_sign1` / `cose_key` are single byte strings, and the canonical
// encoder derives map-key order itself. The only transformation performed
// here is dropping `undefined` optionals (a JS-only artefact with no CBOR
// counterpart — left in place it would encode as the `undefined` simple
// value, which the canonical profile forbids) and, for the signing body,
// removing `sigs`.
//
// Round-trip property: for every record `R` the validator accepts,
//   validatePoeRecord(encodePoeRecord(R)).valid === true
// and the decoded record is `R` (modulo CBOR-canonical key order).

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';

import type { PoeRecord } from './schema';

/** Canonical CBOR bytes of the full record body — the bytes the chunk-array
 * transport carries on chain (see `carriage.ts`). */
export function encodePoeRecord(record: PoeRecord): Uint8Array {
  return encodeCanonicalCbor(toCborValue(record, /* includeSigs */ true));
}

/**
 * Canonical CBOR bytes of the record body **with `sigs` removed** — the body
 * a record-level signature covers. Producers prepend the 25-byte UTF-8 domain
 * prefix `cardano-poe-record-sig-v1` before invoking Ed25519 (the crypto-core
 * helper `buildLabel309SigStructure` handles the prefix and the
 * `Sig_structure` wrapping). Extension keys are part of the signed body and
 * pass through verbatim.
 */
export function encodeRecordBodyForSigning(record: PoeRecord): Uint8Array {
  return encodeCanonicalCbor(toCborValue(record, /* includeSigs */ false));
}

function toCborValue(record: PoeRecord, includeSigs: boolean): CanonicalCborValue {
  const out: { [key: string]: CanonicalCborValue } = {};
  for (const [key, value] of Object.entries(record)) {
    if (value === undefined) continue;
    if (!includeSigs && key === 'sigs') continue;
    out[key] = stripUndefined(value as CanonicalCborValue);
  }
  return out;
}

// Drop `undefined`-valued properties recursively. A typed record reaches the
// encoder with its optional fields either absent or explicitly `undefined`;
// CBOR has no counterpart for the latter (cbor2 would emit the major-type-7
// `undefined` simple value, which the canonical profile rejects on decode),
// so both spell "absent" on the wire.
function stripUndefined(value: CanonicalCborValue): CanonicalCborValue {
  if (value === null || typeof value !== 'object' || value instanceof Uint8Array) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((element) => stripUndefined(element));
  }
  if (value instanceof Map) {
    const out = new Map<string | number, CanonicalCborValue>();
    for (const [k, v] of value) {
      if (v === undefined) continue;
      out.set(k, stripUndefined(v));
    }
    return out;
  }
  const out: { [key: string]: CanonicalCborValue } = {};
  for (const [k, v] of Object.entries(value)) {
    if (v === undefined) continue;
    out[k] = stripUndefined(v as CanonicalCborValue);
  }
  return out;
}
