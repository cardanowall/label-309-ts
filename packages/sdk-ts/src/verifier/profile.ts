// Conformance-profile helpers.
//
// A `core`-profile verifier reading a record that carries `sigs`, `enc`, or
// `merkle` MUST emit `OUT_OF_PROFILE_SKIPPED` (info severity) per affected
// field — NOT `SCHEMA_UNKNOWN_FIELD` (which applies only to fields outside
// the v1 CDDL). This rule lets a block explorer shipping only the `core`
// surface still surface every conformant v1 record regardless of which
// extensions it carries.

import type { PoeRecord, ValidationIssue } from '@cardanowall/poe-standard';

import type { Profile } from './types';
import { PROFILE_RANK } from './types';

export const DEFAULT_PROFILE: Profile = 'recipient-sealed';

export function profileImplements(actual: Profile, required: Profile): boolean {
  return PROFILE_RANK[actual] >= PROFILE_RANK[required];
}

export interface ProfileSkipsResult {
  // info-severity entries emitted when a field belongs to a higher profile
  // than the active one. Surfaces in `validation.info`.
  readonly skips: ValidationIssue[];
  // Convenience flags for the verifier pipeline (whether to enter each
  // sub-pipeline at all).
  readonly verifySignatures: boolean;
  readonly verifyDecrypt: boolean;
}

/**
 * Emit the minimum conformance profile a verifier MUST implement
 * to read this record end-to-end. The profiles form a strict superset chain
 * `core ⊂ signed ⊂ sealed ⊂ recipient-sealed`.
 *
 * The function classifies based on RECORD CONTENT only:
 *   - `'core'`   — no signatures, no sealed items.
 *   - `'signed'` — `record.sigs[]` is present, no sealed items.
 *   - `'sealed'` — any `record.items[i].enc` is present (with or without sigs).
 *
 * The function does NOT return `'recipient-sealed'`: that profile is about
 * VERIFIER CAPABILITY (whether the verifier decrypts with a recipient X25519
 * key), not about record content. A separate helper is required if a caller
 * needs to test whether a particular recipient key can unwrap any slot — see
 * `@cardanowall/crypto-core/sealed-poe` for that pathway.
 */
export function detectConformanceProfile(record: PoeRecord): 'core' | 'signed' | 'sealed' {
  const hasSealedItem =
    Array.isArray(record.items) && record.items.some((it) => it.enc !== undefined);
  if (hasSealedItem) return 'sealed';
  const hasSigs = Array.isArray(record.sigs) && record.sigs.length > 0;
  if (hasSigs) return 'signed';
  return 'core';
}

export function planProfileSkips(profile: Profile, record: PoeRecord): ProfileSkipsResult {
  const skips: ValidationIssue[] = [];
  const has = (k: string): boolean => Object.prototype.hasOwnProperty.call(record, k);
  const verifySignatures = PROFILE_RANK[profile] >= PROFILE_RANK['signed'];
  // The `sealed` rank gates whether the verifier reads the enc envelope at all.
  // There is no separate `sealed`-only sub-pipeline distinct from decryption,
  // so this drives only the skip-emission below rather than a returned flag.
  const readsEnc = PROFILE_RANK[profile] >= PROFILE_RANK['sealed'];
  const verifyDecrypt = PROFILE_RANK[profile] >= PROFILE_RANK['recipient-sealed'];

  if (!verifySignatures && has('sigs')) {
    skips.push({
      code: 'OUT_OF_PROFILE_SKIPPED',
      path: ['sigs'],
      message: `sigs[] requires profile >= 'signed'; active profile is '${profile}'`,
      severity: 'info',
    });
  }
  if (!readsEnc && Array.isArray(record.items)) {
    for (let i = 0; i < record.items.length; i++) {
      if (record.items[i]!.enc === undefined) continue;
      skips.push({
        code: 'OUT_OF_PROFILE_SKIPPED',
        path: ['items', i, 'enc'],
        message: `items[${i}].enc requires profile >= 'sealed'; active profile is '${profile}'`,
        severity: 'info',
      });
    }
  }
  return { skips, verifySignatures, verifyDecrypt };
}
