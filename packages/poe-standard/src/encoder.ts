// CIP-309 v1 record encoder.
//
// Produces canonical CBOR bytes per RFC 8949 §4.2.1 deterministic encoding —
// definite-length, sorted bytewise lex map keys, no duplicates, preferred
// integer/float form. The canonical layer (`@cardanowall/crypto-core/cbor`)
// configures `cbor2` with `cde: true, rejectDuplicateKeys: true`, so the
// encoder's only job is to translate the validator-typed record shape into
// the `CanonicalCborValue` algebra.
//
// Wire-shape contract:
//   - `items[i].hashes` is a CBOR MAP (text-keyed) — not an array of `{alg,h}`.
//   - `merkle[]` is a top-level array, peer to `items` and `sigs`.
//   - Each `sigs[i]` is a CBOR MAP `{cose_sign1, ? cose_key}` (canonical
//     sort places the optional `cose_key` BEFORE `cose_sign1`).
//   - The encryption envelope uses `scheme` (NOT `v`), `aead` (NOT `alg`),
//     `nonce` (NOT `iv`), `slots` (NOT `recipients`), `slots_mac` (NOT
//     `hdr_mac`); the KEM identifier is hoisted to envelope scope as `kem`.
//   - The passphrase block uses key name `passphrase` and `alg = "argon2id"`.
//
// Round-trip property: for every record `R` that the validator accepts,
//   validate(encode(R)).ok === true
//   && validate(encode(R)).record  ≡  R    (modulo CBOR-canonical key sort)

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';

import type {
  EncryptionEnvelope,
  ItemEntry,
  MerkleCommit,
  PassphraseBlock,
  PoeRecord,
  SigEntry,
  Slot,
} from './schema';

type CborMap = { [key: string]: CanonicalCborValue };

export function encodePoeRecord(record: PoeRecord): Uint8Array {
  return encodeCanonicalCbor(recordToCbor(record));
}

// Helper: build the canonical-CBOR `record_body` (the bytes that record-level
// `sigs[i]` signs over). The body is the full record map MINUS the `sigs`
// field; producers prepend the 25-byte UTF-8 domain prefix
// `cardano-poe-record-sig-v1` before invoking Ed25519 (the crypto-core
// helper `buildCip309SigStructure` handles the prefix and `Sig_structure`
// wrapping).
export function encodeRecordBodyForSigning(record: PoeRecord): Uint8Array {
  const body: CborMap = recordToCborInternal(record, /* includeSigs */ false);
  return encodeCanonicalCbor(body);
}

function recordToCbor(record: PoeRecord): CanonicalCborValue {
  return recordToCborInternal(record, /* includeSigs */ true);
}

function recordToCborInternal(record: PoeRecord, includeSigs: boolean): CborMap {
  const out: CborMap = { v: record.v };
  if (record.items !== undefined) out['items'] = record.items.map(itemToCbor);
  if (record.merkle !== undefined) out['merkle'] = record.merkle.map(merkleToCbor);
  if (record.supersedes !== undefined) out['supersedes'] = record.supersedes;
  if (includeSigs && record.sigs !== undefined) out['sigs'] = record.sigs.map(sigEntryToCbor);
  if (record.crit !== undefined) out['crit'] = record.crit.slice();
  // Preserve extension keys verbatim — they are part of the signed
  // `record_body` and MUST round-trip byte-identical.
  for (const [k, v] of Object.entries(record)) {
    if (
      k === 'v' ||
      k === 'items' ||
      k === 'merkle' ||
      k === 'supersedes' ||
      k === 'sigs' ||
      k === 'crit'
    ) {
      continue;
    }
    out[k] = v as CanonicalCborValue;
  }
  return out;
}

function itemToCbor(item: ItemEntry): CanonicalCborValue {
  const out: CborMap = { hashes: hashesToCbor(item.hashes) };
  if (item.uris !== undefined) {
    out['uris'] = item.uris.map((chunks) => chunks.slice());
  }
  if (item.enc !== undefined) {
    out['enc'] = envelopeToCbor(item.enc as EncryptionEnvelope);
  }
  return out;
}

function hashesToCbor(hashes: Readonly<Record<string, Uint8Array>>): CanonicalCborValue {
  // text-keyed CBOR map — canonical sort orders by encoded-key bytewise lex
  // automatically (`sha2-256` `0x68` precedes `blake2b-256` `0x6b`).
  const out: CborMap = {};
  for (const [alg, digest] of Object.entries(hashes)) {
    out[alg] = digest;
  }
  return out;
}

function merkleToCbor(commit: MerkleCommit): CanonicalCborValue {
  const out: CborMap = {
    alg: commit.alg,
    root: commit.root,
    leaf_count: commit.leaf_count,
  };
  if (commit.uris !== undefined) {
    out['uris'] = commit.uris.map((chunks) => chunks.slice());
  }
  return out;
}

function envelopeToCbor(enc: EncryptionEnvelope): CanonicalCborValue {
  const out: CborMap = {
    scheme: enc.scheme as CanonicalCborValue,
    aead: enc.aead,
    nonce: enc.nonce,
  };
  if (enc.kem !== undefined) out['kem'] = enc.kem;
  if (enc.slots !== undefined) out['slots'] = enc.slots.map(slotToCbor);
  if (enc.slots_mac !== undefined) out['slots_mac'] = enc.slots_mac;
  if (enc.passphrase !== undefined) out['passphrase'] = passphraseToCbor(enc.passphrase);
  return out;
}

function slotToCbor(slot: Slot): CanonicalCborValue {
  // KEM-driven slot serialization. The canonical encoder sorts map keys by
  // length-then-bytewise (RFC 8949 §4.2.1), so it emits `wrap` (4-byte key)
  // before `kem_ct` (6-byte key) and `epk` (3-byte key) before `wrap`
  // automatically — insertion order here is irrelevant to the wire bytes.
  //
  //   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }`
  //   - mlkem768x25519: `{ kem_ct: [ bstr, ... ], wrap: bstr(48) }` — `kem_ct`
  //     is the already-chunked array (NOT re-chunked here), so the bytes match
  //     what crypto-core committed to `slots_mac` byte-for-byte.
  if (slot.kem_ct !== undefined) {
    return { kem_ct: slot.kem_ct.map((c) => c), wrap: slot.wrap! };
  }
  return { epk: slot.epk!, wrap: slot.wrap! };
}

function passphraseToCbor(pp: PassphraseBlock): CanonicalCborValue {
  return {
    alg: pp.alg,
    salt: pp.salt,
    params: pp.params as { readonly [key: string]: CanonicalCborValue },
  };
}

function sigEntryToCbor(entry: SigEntry): CanonicalCborValue {
  const out: CborMap = { cose_sign1: entry.cose_sign1.map((b) => b) };
  if (entry.cose_key !== undefined) {
    out['cose_key'] = entry.cose_key.map((b) => b);
  }
  return out;
}
