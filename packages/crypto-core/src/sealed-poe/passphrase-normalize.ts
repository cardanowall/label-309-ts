// cardano-poe-pw-norm-v1: the normative passphrase normalization profile.
//
// Two implementations MUST derive a byte-identical CEK from the same
// passphrase, so the normalization applied before Argon2id is pinned, in
// order:
//
//   1. Bound the raw input (a pre-KDF denial-of-service backstop).
//   2. NFKC under the pinned Unicode 16.0.0 tables. Input the pinned tables
//      cannot normalize stably — an unpaired surrogate, or a code point that
//      Unicode 16.0 leaves unassigned (a later Unicode version may give it a
//      decomposition and silently change the derived key) — is rejected.
//   3. Collapse every maximal run of White_Space characters to one U+0020.
//   4. Trim leading/trailing U+0020.
//   5. Reject the empty result — a whitespace-only passphrase normalizes to
//      zero bytes, which Argon2id would silently accept, keying the record to
//      a CEK any party can derive.
//   6. UTF-8-encode; those bytes are the Argon2id password input.
//
// Every Unicode-sensitive step resolves against the pinned Unicode 16.0.0
// data — the NFKC tables and the White_Space property both — never the host
// engine, whose tables float with its Unicode version.

import { Nfkc16Error, isWhiteSpace16, nfkc16 } from '../unicode/nfkc16';
import { EciesSealedPoeError } from './errors';

// Reference bound on the RAW UTF-8 byte length of a passphrase, enforced before
// any normalization or hashing work. A deployment-pinned constant, not a wire
// field; deployments MAY tighten it.
export const MAX_PASSPHRASE_INPUT_BYTES = 4096;

const UTF8 = new TextEncoder();

// One code-point pass implementing profile steps 3 + 4: each maximal
// White_Space run becomes a single U+0020, and a leading or trailing run is
// dropped entirely (never emitted), which is exactly collapse-then-trim.
// `isWhiteSpace16` is the pinned Unicode 16.0 White_Space property —
// deliberately NOT JavaScript's `\s`, which also matches U+FEFF, a character
// the property (and therefore the profile) does not treat as whitespace.
function collapseAndTrimWhiteSpace(input: string): string {
  let out = '';
  let pendingRun = false;
  for (const ch of input) {
    if (isWhiteSpace16(ch.codePointAt(0) as number)) {
      pendingRun = true;
      continue;
    }
    if (pendingRun && out.length > 0) {
      out += ' ';
    }
    pendingRun = false;
    out += ch;
  }
  return out;
}

// Apply the cardano-poe-pw-norm-v1 profile and return the exact Argon2id
// password bytes. Throws PASSPHRASE_INPUT_TOO_LONG when the raw input exceeds
// the pre-normalization bound, ENC_PASSPHRASE_UNNORMALIZABLE when the input
// cannot normalize stably under Unicode 16.0 (an unpaired surrogate or an
// unassigned code point), and ENC_PASSPHRASE_EMPTY when the normalized result
// is the empty string.
export function normalizePassphrase(passphrase: string): Uint8Array {
  const rawBytes = UTF8.encode(passphrase);
  if (rawBytes.length > MAX_PASSPHRASE_INPUT_BYTES) {
    throw new EciesSealedPoeError(
      'PASSPHRASE_INPUT_TOO_LONG',
      `passphrase raw UTF-8 length ${rawBytes.length} exceeds MAX_PASSPHRASE_INPUT_BYTES=${MAX_PASSPHRASE_INPUT_BYTES}`,
    );
  }
  let folded: string;
  try {
    folded = nfkc16(passphrase);
  } catch (error) {
    if (error instanceof Nfkc16Error) {
      throw new EciesSealedPoeError('ENC_PASSPHRASE_UNNORMALIZABLE', error.message, {
        cause: error,
      });
    }
    throw error;
  }
  const normalized = collapseAndTrimWhiteSpace(folded);
  if (normalized.length === 0) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_EMPTY',
      'passphrase normalizes to the empty string',
    );
  }
  return UTF8.encode(normalized);
}
