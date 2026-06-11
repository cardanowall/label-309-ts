// Position-aware CBOR walker for byte-faithful transaction dissection.
//
// The verifier MUST fetch raw transaction CBOR and slice its components
// VERBATIM (never decode-then-re-encode). A re-encode pass would silently
// launder a non-conformant on-chain record into a conformant one — a CBOR
// decoder normalises non-canonical input (sorts map keys, collapses
// indefinite-length encodings) — and would break both integrity bindings,
// which are defined over the bytes exactly as fetched:
//
//   * blake2b-256(transaction-body bytes)  == the transaction id;
//   * blake2b-256(auxiliary-data bytes)    == the body's auxiliary_data_hash.
//
// This module owns three byte-level concerns:
//
//   * `sliceTxComponents`        — split a transaction into the exact body /
//                                  witness-set / auxiliary-data byte slices.
//   * `unwrapAuxiliaryData`      — unwrap auxiliary-data bytes down to the
//                                  raw label-309 value, accepting all three
//                                  Conway-era envelope forms and dispatching
//                                  on the top-level CBOR type and tag ONLY
//                                  (never on map-key inspection).
//   * `auxiliaryDataHashFromTxBody` — read the body's `auxiliary_data_hash`
//                                  field (key 7) for the integrity binding.
//
// Chunk-array reassembly of the label-309 value is NOT here: it is the
// shared transport step `reassembleLabel309Value` in
// `@cardanowall/poe-standard/carriage`.

interface CborHead {
  readonly mt: number;
  readonly ai: number;
  readonly payloadStart: number;
  readonly valueU64: number;
}

function readHead(bytes: Uint8Array, pos: number): CborHead {
  if (pos >= bytes.length) {
    throw new RangeError('MALFORMED_CBOR: truncated input (no head byte)');
  }
  const head = bytes[pos]!;
  const mt = head >> 5;
  const ai = head & 0x1f;
  let p = pos + 1;
  let valueU64: number;

  if (ai < 24) {
    valueU64 = ai;
  } else if (ai === 24) {
    if (p + 1 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 1-byte argument');
    }
    valueU64 = bytes[p]!;
    p += 1;
  } else if (ai === 25) {
    if (p + 2 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 2-byte argument');
    }
    valueU64 = (bytes[p]! << 8) | bytes[p + 1]!;
    p += 2;
  } else if (ai === 26) {
    if (p + 4 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 4-byte argument');
    }
    valueU64 =
      bytes[p]! * 0x1000000 + ((bytes[p + 1]! << 16) | (bytes[p + 2]! << 8) | bytes[p + 3]!);
    p += 4;
  } else if (ai === 27) {
    if (p + 8 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 8-byte argument');
    }
    let n = 0;
    for (let k = 0; k < 8; k++) n = n * 256 + bytes[p + k]!;
    if (n > Number.MAX_SAFE_INTEGER) {
      throw new RangeError('MALFORMED_CBOR: 8-byte argument exceeds JavaScript safe integer range');
    }
    valueU64 = n;
    p += 8;
  } else if (ai === 31) {
    throw new RangeError(
      'MALFORMED_CBOR: indefinite-length encoding (ai=31) not allowed under canonical CBOR',
    );
  } else {
    throw new RangeError(`MALFORMED_CBOR: reserved additional info ai=${ai}`);
  }

  return { mt, ai, payloadStart: p, valueU64 };
}

function skipCborItem(bytes: Uint8Array, pos: number): number {
  const h = readHead(bytes, pos);
  let p = h.payloadStart;
  switch (h.mt) {
    case 0:
    case 1:
      return p;
    case 2:
    case 3:
      if (p + h.valueU64 > bytes.length) {
        throw new RangeError(
          `MALFORMED_CBOR: truncated ${h.mt === 2 ? 'byte' : 'text'} string payload`,
        );
      }
      return p + h.valueU64;
    case 4:
      for (let i = 0; i < h.valueU64; i++) p = skipCborItem(bytes, p);
      return p;
    case 5:
      for (let i = 0; i < h.valueU64 * 2; i++) p = skipCborItem(bytes, p);
      return p;
    case 6:
      return skipCborItem(bytes, p);
    case 7: {
      if (h.ai < 24) return p;
      if (h.ai === 24) {
        if (p + 1 > bytes.length) {
          throw new RangeError('MALFORMED_CBOR: truncated simple value');
        }
        return p + 1;
      }
      if (h.ai === 25 || h.ai === 26 || h.ai === 27) return p;
      throw new RangeError(`MALFORMED_CBOR: unsupported major-7 ai=${h.ai}`);
    }
    default:
      throw new RangeError(`MALFORMED_CBOR: unknown major type ${h.mt}`);
  }
}

// CBOR tag 259 wraps the keyed-map auxiliary-data form (Conway).
const CARDANO_AUX_DATA_TAG = 259;
const POE_LABEL = 309;
const AUX_DATA_HASH_BODY_KEY = 7;

/**
 * Byte-faithful components of a Cardano transaction, located by walking the
 * tx CBOR without a decode-then-re-encode pass.
 *
 * Every field is an EXACT on-chain byte slice: `blake2b256(txBody)` equals the
 * transaction id, `blake2b256(auxiliaryData)` equals the body's
 * `auxiliary_data_hash`, and the witness set decodes to the vkey witnesses
 * that authorised the transaction. `auxiliaryData` is `null` when the
 * transaction carries none (CBOR null/undefined at the auxiliary-data
 * position).
 */
export interface TxComponents {
  readonly txBody: Uint8Array;
  readonly witnessSet: Uint8Array;
  readonly auxiliaryData: Uint8Array | null;
}

/**
 * Walk the transaction CBOR once and return its byte-faithful components.
 * Accepts the four-element post-Alonzo shape `[body, witness_set, is_valid,
 * auxiliary_data]` and the three-element pre-Alonzo shape
 * `[body, witness_set, auxiliary_data]`. Throws
 * `RangeError("MALFORMED_CBOR: …")` on structural violations.
 */
export function sliceTxComponents(txCbor: Uint8Array): TxComponents {
  const txHead = readHead(txCbor, 0);
  if (txHead.mt !== 4) {
    throw new RangeError(`MALFORMED_CBOR: tx CBOR is not a CBOR array (major type ${txHead.mt})`);
  }
  if (txHead.valueU64 !== 3 && txHead.valueU64 !== 4) {
    throw new RangeError(
      `MALFORMED_CBOR: tx CBOR array has ${txHead.valueU64} elements; expected 3 ([body, witness_set, auxiliary_data]) or 4 ([body, witness_set, is_valid, auxiliary_data])`,
    );
  }

  const bodyStart = txHead.payloadStart;
  const bodyEnd = skipCborItem(txCbor, bodyStart);
  const witnessSetStart = bodyEnd;
  const witnessSetEnd = skipCborItem(txCbor, witnessSetStart);
  const auxStart = txHead.valueU64 === 4 ? skipCborItem(txCbor, witnessSetEnd) : witnessSetEnd; // skip is_valid in the four-element shape

  const txBody = txCbor.slice(bodyStart, bodyEnd);
  const witnessSet = txCbor.slice(witnessSetStart, witnessSetEnd);

  if (auxStart >= txCbor.length) {
    throw new RangeError('MALFORMED_CBOR: truncated tx (auxiliary_data missing)');
  }
  const auxFirstByte = txCbor[auxStart]!;
  if (auxFirstByte === 0xf6 || auxFirstByte === 0xf7) {
    return { txBody, witnessSet, auxiliaryData: null };
  }
  const auxEnd = skipCborItem(txCbor, auxStart);
  return { txBody, witnessSet, auxiliaryData: txCbor.slice(auxStart, auxEnd) };
}

/**
 * The unwrapped view of one auxiliary-data value: the raw label-309 value
 * bytes (the transport chunk array exactly as carried; `null` when the
 * metadata carries no label-309 entry) plus the ascending-sorted list of
 * every metadata label present.
 */
export interface UnwrappedAuxiliaryData {
  readonly label309: Uint8Array | null;
  readonly metadataLabels: ReadonlyArray<number>;
}

/**
 * Unwrap auxiliary-data bytes down to the label-309 value. All three
 * Conway-era envelope forms are accepted, dispatching PURELY on the top-level
 * CBOR type and tag:
 *
 *   * tag 259            → keyed map; the metadata map sits under integer key 0;
 *   * untagged array     → the two-element `[ transaction_metadata,
 *                          auxiliary_scripts ]` form; the metadata map is
 *                          element 0;
 *   * untagged map       → ALWAYS the metadata map itself.
 *
 * Map keys are never inspected to guess the shape — a metadata map is keyed
 * by integer labels, so any key-sniffing heuristic would silently mis-parse
 * legitimate metadata (e.g. a metadata map whose only label is 0). Any other
 * top-level shape, and any tag other than 259, throws
 * `RangeError("MALFORMED_CBOR: …")`.
 *
 * A tag-259 map with no key 0, and a metadata map with no entry under label
 * 309, are well-formed auxiliary data that simply carry no PoE record —
 * `label309` is `null` and the caller emits METADATA_NOT_FOUND.
 */
export function unwrapAuxiliaryData(auxBytes: Uint8Array): UnwrappedAuxiliaryData {
  const head = readHead(auxBytes, 0);
  let metadataMapPos: number | null;

  if (head.mt === 6) {
    if (head.valueU64 !== CARDANO_AUX_DATA_TAG) {
      throw new RangeError(
        `MALFORMED_CBOR: auxiliary data carries CBOR tag ${head.valueU64}; only tag ${CARDANO_AUX_DATA_TAG} is an auxiliary-data envelope`,
      );
    }
    const inner = readHead(auxBytes, head.payloadStart);
    if (inner.mt !== 5) {
      throw new RangeError(
        `MALFORMED_CBOR: tag-${CARDANO_AUX_DATA_TAG} auxiliary data must wrap a map (major type ${inner.mt})`,
      );
    }
    // Find integer key 0 (the transaction_metadata entry); other keys carry
    // scripts and are skipped without inspection.
    metadataMapPos = null;
    let entryPos = inner.payloadStart;
    for (let i = 0; i < inner.valueU64; i++) {
      const keyHead = readHead(auxBytes, entryPos);
      const valuePos = skipCborItem(auxBytes, entryPos);
      if (keyHead.mt === 0 && keyHead.valueU64 === 0) {
        metadataMapPos = valuePos;
      }
      entryPos = skipCborItem(auxBytes, valuePos);
    }
  } else if (head.mt === 4) {
    if (head.valueU64 !== 2) {
      throw new RangeError(
        `MALFORMED_CBOR: untagged auxiliary-data array must be the two-element [transaction_metadata, auxiliary_scripts] form (got ${head.valueU64} elements)`,
      );
    }
    metadataMapPos = head.payloadStart;
  } else if (head.mt === 5) {
    // An untagged map is always the metadata map itself.
    metadataMapPos = 0;
  } else {
    throw new RangeError(
      `MALFORMED_CBOR: auxiliary data has major type ${head.mt}; expected map, array, or tag ${CARDANO_AUX_DATA_TAG}`,
    );
  }

  if (metadataMapPos === null) {
    return { label309: null, metadataLabels: [] };
  }

  const metaHead = readHead(auxBytes, metadataMapPos);
  if (metaHead.mt !== 5) {
    throw new RangeError(
      `MALFORMED_CBOR: transaction metadata is not a CBOR map (major type ${metaHead.mt})`,
    );
  }
  const labels: number[] = [];
  let label309: Uint8Array | null = null;
  let pairPos = metaHead.payloadStart;
  for (let i = 0; i < metaHead.valueU64; i++) {
    const keyHead = readHead(auxBytes, pairPos);
    // The ledger pins metadata labels as unsigned integers; any other key
    // type cannot appear in on-chain transaction metadata.
    if (keyHead.mt !== 0) {
      throw new RangeError(
        `MALFORMED_CBOR: metadata map key has major type ${keyHead.mt}; metadata labels are unsigned integers`,
      );
    }
    const keyVal = keyHead.valueU64;
    labels.push(keyVal);
    const valueStart = skipCborItem(auxBytes, pairPos);
    const valueEnd = skipCborItem(auxBytes, valueStart);
    if (keyVal === POE_LABEL) {
      label309 = auxBytes.slice(valueStart, valueEnd);
    }
    pairPos = valueEnd;
  }
  labels.sort((a, b) => a - b);
  return { label309, metadataLabels: labels };
}

/**
 * Read the transaction body's `auxiliary_data_hash` (body-map key 7) as an
 * exact byte slice; `null` when the body carries no key 7. Throws
 * `RangeError("MALFORMED_CBOR: …")` when the body is not a CBOR map.
 */
export function auxiliaryDataHashFromTxBody(txBody: Uint8Array): Uint8Array | null {
  const head = readHead(txBody, 0);
  if (head.mt !== 5) {
    throw new RangeError(
      `MALFORMED_CBOR: transaction body is not a CBOR map (major type ${head.mt})`,
    );
  }
  let pairPos = head.payloadStart;
  for (let i = 0; i < head.valueU64; i++) {
    const keyHead = readHead(txBody, pairPos);
    const valueStart = skipCborItem(txBody, pairPos);
    const valueEnd = skipCborItem(txBody, valueStart);
    if (keyHead.mt === 0 && keyHead.valueU64 === AUX_DATA_HASH_BODY_KEY) {
      const valueHead = readHead(txBody, valueStart);
      if (valueHead.mt !== 2) {
        throw new RangeError(
          `MALFORMED_CBOR: auxiliary_data_hash (body key 7) is not a byte string (major type ${valueHead.mt})`,
        );
      }
      return txBody.slice(valueHead.payloadStart, valueEnd);
    }
    pairPos = valueEnd;
  }
  return null;
}
