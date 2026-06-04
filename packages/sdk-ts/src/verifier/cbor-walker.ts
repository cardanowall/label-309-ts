// Position-aware CBOR walker for byte-faithful label-309 metadata extraction.
//
// The verifier MUST fetch raw transaction CBOR and extract the label-309
// value VERBATIM (not via decode-then-re-encode). A
// re-encode pass would silently launder a non-conformant on-chain record into
// a conformant one because cbor2's decoder normalises non-canonical input
// (sorts map keys, collapses indefinite-length encodings, etc.); the
// structural validator's canonical-CBOR check (`decodeCanonicalCbor` +
// cbor2 CDE options) only catches the violation if it sees the producer's
// original bytes.
//
// Pure stdlib walker (no `cbor2` dependency for the slicing path). Rejects
// indefinite-length encodings, which canonical CBOR forbids; the structural
// validator downstream performs the rest of the deterministic-encoding checks.

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

// CBOR tag 259 wraps post-Alonzo auxiliary_data (CIP-29).
const CARDANO_AUX_DATA_TAG = 259;
const POE_LABEL = 309;

/**
 * Byte-faithful components of a Cardano transaction, located by walking the
 * tx CBOR without a decode-then-re-encode pass.
 *
 * `txBody` and `witnessSet` are EXACT on-chain byte slices: `blake2b256(txBody)`
 * equals the transaction hash, and the witness set decodes to the vkey
 * witnesses that authorised the transaction. The slices are produced by the
 * same position-aware walk that finds label 309, so they never round-trip
 * through a CBOR re-encoder.
 *
 * `label309` is the reassembled label-309 value (chunked-bytes concatenated;
 * see `reassembleLabel309Value`), `null` when auxiliary_data is null/undefined
 * or label 309 is absent. `auxMetadataLabels` is the ascending-sorted list of
 * every integer key in the auxiliary metadata map (`[]` when aux is null).
 */
export interface TxComponents {
  readonly label309: Uint8Array | null;
  readonly txBody: Uint8Array;
  readonly witnessSet: Uint8Array;
  readonly auxMetadataLabels: number[];
}

/**
 * Walk the transaction CBOR once and return its byte-faithful components.
 *
 * Throws `RangeError("MALFORMED_CBOR: …")` on structural violations. The body
 * and witness-set slices are the producer's ORIGINAL bytes; `label309` carries
 * the same byte-faithful guarantee `sliceLabel309Value` documents (no
 * decode-then-re-encode, so non-canonical encodings reach the structural
 * validator unchanged).
 */
export function sliceTxComponents(txCbor: Uint8Array): TxComponents {
  const txHead = readHead(txCbor, 0);
  if (txHead.mt !== 4) {
    throw new RangeError(`MALFORMED_CBOR: tx CBOR is not a CBOR array (major type ${txHead.mt})`);
  }
  if (txHead.valueU64 < 4) {
    throw new RangeError(
      `MALFORMED_CBOR: tx CBOR array has ${txHead.valueU64} elements; expected >= 4 (post-Conway: [body, witness_set, is_valid, auxiliary_data])`,
    );
  }

  const bodyStart = txHead.payloadStart;
  const bodyEnd = skipCborItem(txCbor, bodyStart);
  const witnessSetStart = bodyEnd;
  const witnessSetEnd = skipCborItem(txCbor, witnessSetStart);
  const pos = skipCborItem(txCbor, witnessSetEnd); // skip is_valid

  const txBody = txCbor.slice(bodyStart, bodyEnd);
  const witnessSet = txCbor.slice(witnessSetStart, witnessSetEnd);

  if (pos >= txCbor.length) {
    throw new RangeError('MALFORMED_CBOR: truncated tx (auxiliary_data missing)');
  }
  const auxFirstByte = txCbor[pos]!;
  if (auxFirstByte === 0xf6 || auxFirstByte === 0xf7) {
    return { label309: null, txBody, witnessSet, auxMetadataLabels: [] };
  }

  let auxMapPos = pos;
  const auxHead = readHead(txCbor, pos);
  if (auxHead.mt === 6) {
    if (auxHead.valueU64 !== CARDANO_AUX_DATA_TAG) {
      throw new RangeError(
        `MALFORMED_CBOR: auxiliary_data carries unexpected CBOR tag ${auxHead.valueU64}; expected ${CARDANO_AUX_DATA_TAG} or bare map`,
      );
    }
    auxMapPos = auxHead.payloadStart;
  }

  const mapHead = readHead(txCbor, auxMapPos);
  if (mapHead.mt !== 5) {
    throw new RangeError(
      `MALFORMED_CBOR: auxiliary_data is not a CBOR map (major type ${mapHead.mt})`,
    );
  }

  // Disambiguate the tagged (post-Alonzo, `{0 → metadata, 1 → ...}`) and bare
  // (pre-Alonzo, the map IS the metadata map directly) auxiliary_data shapes
  // by walking the map keys: if any int key in `{0,1,2,3}` is present, treat
  // it as the post-Alonzo shape and find key 0; else treat the whole map as
  // metadata directly. Modern Cardano txs (Conway+) are always tag-259
  // wrapped, but synthetic test fixtures often emit the post-Alonzo shape
  // bare and we want to handle both without forcing producers to add the tag.
  let metadataMapPos: number | null;
  {
    let entryPos = mapHead.payloadStart;
    let sawAuxKey = false;
    let foundMetadataAt: number | null = null;
    for (let i = 0; i < mapHead.valueU64; i++) {
      const keyHead = readHead(txCbor, entryPos);
      if (keyHead.mt === 0 && keyHead.valueU64 <= 3) {
        sawAuxKey = true;
        if (keyHead.valueU64 === 0) {
          foundMetadataAt = keyHead.payloadStart;
        }
      }
      entryPos = skipCborItem(txCbor, entryPos); // skip key
      entryPos = skipCborItem(txCbor, entryPos); // skip value
    }
    if (sawAuxKey || auxHead.mt === 6) {
      metadataMapPos = foundMetadataAt;
    } else {
      // Bare pre-Alonzo metadata map.
      metadataMapPos = auxMapPos;
    }
  }

  if (metadataMapPos === null) {
    return { label309: null, txBody, witnessSet, auxMetadataLabels: [] };
  }

  const metaHead = readHead(txCbor, metadataMapPos);
  if (metaHead.mt !== 5) {
    throw new RangeError(`MALFORMED_CBOR: metadata is not a CBOR map (major type ${metaHead.mt})`);
  }
  const labels: number[] = [];
  let label309: Uint8Array | null = null;
  let pairPos = metaHead.payloadStart;
  for (let i = 0; i < metaHead.valueU64; i++) {
    const keyHead = readHead(txCbor, pairPos);
    const keyVal = decodeIntKey(keyHead);
    labels.push(keyVal);
    const valueStart = skipCborItem(txCbor, pairPos);
    const valueEnd = skipCborItem(txCbor, valueStart);
    if (keyVal === POE_LABEL) {
      label309 = reassembleLabel309Value(txCbor, valueStart, valueEnd);
    }
    pairPos = valueEnd;
  }
  labels.sort((a, b) => a - b);
  return { label309, txBody, witnessSet, auxMetadataLabels: labels };
}

/**
 * Extract the byte slice corresponding to the value under metadata label 309.
 * Returns `null` when auxiliary_data is null/undefined or when label 309 is
 * absent. Throws `RangeError("MALFORMED_CBOR: …")` on structural violations.
 *
 * Returns the producer's ORIGINAL on-chain bytes — no decode-then-re-encode
 * pass. The structural validator MUST receive these bytes verbatim so
 * non-canonical encodings surface as `MALFORMED_CBOR` rather than being
 * silently laundered.
 */
export function sliceLabel309Value(txCbor: Uint8Array): Uint8Array | null {
  return sliceTxComponents(txCbor).label309;
}

/**
 * Cardano caps individual metadata `bstr` / `tstr` values at 64 bytes
 * (Cardano metadata spec). A Label 309 PoE record's
 * canonical CBOR is typically several hundred bytes, so the producer emits
 * it as a `bytes-chunk-array` — `[ bstr .size (1..64), … ]` — at the
 * label-309 value position. The verifier MUST byte-concatenate the chunks
 * IN ORDER before passing the result to `validatePoeRecord`, otherwise
 * the canonical-CBOR decoder sees an outer CBOR array of byte strings
 * instead of the inner CBOR map and the record fails with
 * `SCHEMA_TYPE_MISMATCH` / `MALFORMED_CBOR`.
 *
 * Small records (≤ 64 bytes) MAY be emitted as a single `bstr` directly.
 * For backwards-compat we also accept a bare CBOR map value — older
 * producers and small synthetic fixtures use that shape.
 *
 * Returns the canonical-CBOR PoE record body (a `bstr`-free, map-rooted
 * byte sequence) ready for validation.
 */
function reassembleLabel309Value(
  txCbor: Uint8Array,
  valueStart: number,
  valueEnd: number,
): Uint8Array {
  const head = readHead(txCbor, valueStart);
  // Major type 4 = array → assume bytes-chunk-array; concatenate inner bstr items.
  if (head.mt === 4) {
    const out: Uint8Array[] = [];
    let totalLen = 0;
    let chunkPos = head.payloadStart;
    for (let i = 0; i < head.valueU64; i++) {
      const chunkHead = readHead(txCbor, chunkPos);
      if (chunkHead.mt !== 2) {
        throw new RangeError(
          `MALFORMED_CBOR: label-309 value is a CBOR array but element ${i} has major type ${chunkHead.mt}; expected byte string (chunked-bytes shape)`,
        );
      }
      const chunkValueStart = chunkHead.payloadStart;
      const chunkValueEnd = chunkValueStart + chunkHead.valueU64;
      out.push(txCbor.slice(chunkValueStart, chunkValueEnd));
      totalLen += chunkHead.valueU64;
      chunkPos = chunkValueEnd;
    }
    const concat = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of out) {
      concat.set(c, offset);
      offset += c.length;
    }
    return concat;
  }
  // Major type 2 = single bstr value. The bstr CONTENTS are the canonical
  // CBOR record body — strip the bstr head so decodeCanonicalCbor sees the
  // map directly.
  if (head.mt === 2) {
    return txCbor.slice(head.payloadStart, head.payloadStart + head.valueU64);
  }
  // Major type 5 = map directly (bare-canonical shape; some synthetic
  // fixtures emit this when the record fits in one chunk and the producer
  // chose not to box it in a bstr). Pass through unchanged.
  if (head.mt === 5) {
    return txCbor.slice(valueStart, valueEnd);
  }
  throw new RangeError(
    `MALFORMED_CBOR: label-309 value has major type ${head.mt}; expected array (chunked), byte string, or map`,
  );
}

function decodeIntKey(h: CborHead): number {
  if (h.mt === 0) return h.valueU64;
  if (h.mt === 1) return -1 - h.valueU64;
  throw new RangeError(
    `MALFORMED_CBOR: metadata map key has major type ${h.mt}; expected unsigned integer`,
  );
}
