// Shared cross-language verdict projection.
//
// `NormalizedSigVerdict` is the test-only common surface that BOTH the TS KAT
// test (this file's consumer) and the Python parity twin compute from their
// native verifier output. The fixture's `expected_normalized_verdict` field is
// the single source of truth; both languages deep-equal-assert against it.
//
// Why a projection rather than the raw verifier output:
//   * The TS verifier emits a 4-state
//     `verdict: 'valid' | 'invalid' | 'unsupported' | 'unresolved'`.
//   * The Python verifier emits a 2-state `valid: bool`.
// The projection collapses TS's `verdict === 'valid'` to `ok: true` and
// everything else (including `'unsupported'` / `'unresolved'`) to `ok: false`
// with the corresponding `reason` preserved.
//
// This file lives under `tests/` (test-only utility) — never under `src/`.

import type { VerifyRecordSignature } from '@cardanowall/sdk-ts/verifier';

export interface NormalizedSigVerdict {
  readonly index: number;
  readonly signer_pub_hex: string | null;
  readonly signer_type: 'in-signature-kid' | 'wallet-inline-key' | null;
  readonly ok: boolean;
  readonly reason: string | null;
}

export function toNormalizedSigVerdict(v: VerifyRecordSignature): NormalizedSigVerdict {
  return {
    index: v.index,
    signer_pub_hex: v.signerPub ?? null,
    signer_type: v.signerType ?? null,
    ok: v.verdict === 'valid',
    reason: v.reason ?? null,
  };
}
