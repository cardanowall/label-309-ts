// The single seam that turns a structurally-validated but permissive on-wire
// `enc` block into the discriminated `SealedEnvelope` the unwrap / trial-decrypt
// path consumes.
//
// Every read-path consumer (inbox trial-decrypt, inbox CEK recovery, the CLI
// `inbox sync` / `inbox decrypt` orchestrators, the standalone recipient
// verifier) used to do this inline with a HARDCODED `kem: 'x25519'` and an
// unconditional `slots.map(s => ({ epk: s.epk, wrap: s.wrap }))`. With the
// discriminated-union slot shape (classical `{epk, wrap}` vs hybrid
// `{kem_ct, wrap}`) that inline build is both wrong (drops `kem_ct`) and
// uncompilable (reads optional `epk` as required). This helper is the ONE place
// the conversion lives: it dispatches on `enc.kem`, picks the matching per-slot
// fields, and returns `null` for anything that is not a recognised sealed
// envelope (passphrase-only blocks, missing slots, unknown KEM). Callers then
// pass the whole returned envelope plus their `RecipientKeyBundle` straight to
// `eciesSealedPoeUnwrap` / `eciesSealedPoeTrialDecrypt` — they never rebuild
// slots or reassemble `kem_ct` themselves.
//
// crypto-core is a leaf package and must not depend on poe-standard's Zod
// schema, so the input is a structural shape mirroring the fields the parsed
// `EncryptionEnvelope` exposes. Anything narrower (per-slot length checks) is
// re-asserted by `assertEnvelopeStructure` inside the unwrap path; this helper
// is purely the KEM-driven shape projection.

import type { Mlkem768X25519Slot, SealedEnvelope, X25519Slot } from './wrap';

// Structural mirror of the parsed-but-permissive on-wire slot. Each field is
// `T | undefined` (not just optional) so the parsed `EncryptionEnvelope` from a
// consumer compiled with `exactOptionalPropertyTypes` is assignable without a
// cast: the schema layer cannot know the envelope `kem` from a slot in
// isolation, so it leaves all three fields optional (see poe-standard
// SlotSchema).
export interface ParsedSlotShape {
  readonly epk?: Uint8Array | undefined;
  readonly kem_ct?: ReadonlyArray<Uint8Array> | undefined;
  readonly wrap?: Uint8Array | undefined;
}

// Structural mirror of the parsed-but-permissive `enc` block.
export interface ParsedEnvelopeShape {
  readonly scheme?: unknown;
  readonly aead?: string | undefined;
  readonly kem?: string | undefined;
  readonly nonce?: Uint8Array | undefined;
  readonly slots?: ReadonlyArray<ParsedSlotShape> | undefined;
  readonly slots_mac?: Uint8Array | undefined;
}

// Build the discriminated `SealedEnvelope` from a parsed `enc` block, or return
// `null` when the block is not a sealed-recipient envelope we can trial-decrypt
// (passphrase-only, missing slots/nonce/slots_mac, unrecognised KEM, or a slot
// missing the KEM's required field). Returning `null` keeps every consumer's
// "this item is not for the recipient path → no match, no crypto" branch.
export function sealedEnvelopeFromParsed(enc: ParsedEnvelopeShape): SealedEnvelope | null {
  if (enc.scheme !== 1 || enc.aead !== 'xchacha20-poly1305') return null;
  if (enc.nonce === undefined || enc.slots_mac === undefined) return null;
  const slots = enc.slots;
  if (slots === undefined || slots.length < 1) return null;

  if (enc.kem === 'x25519') {
    const x25519Slots: X25519Slot[] = [];
    for (const s of slots) {
      if (s.epk === undefined || s.wrap === undefined) return null;
      x25519Slots.push({ epk: s.epk, wrap: s.wrap });
    }
    return {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce: enc.nonce,
      slots: x25519Slots,
      slots_mac: enc.slots_mac,
    };
  }

  if (enc.kem === 'mlkem768x25519') {
    const hybridSlots: Mlkem768X25519Slot[] = [];
    for (const s of slots) {
      if (s.kem_ct === undefined || s.wrap === undefined) return null;
      hybridSlots.push({ kem_ct: s.kem_ct, wrap: s.wrap });
    }
    return {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'mlkem768x25519',
      nonce: enc.nonce,
      slots: hybridSlots,
      slots_mac: enc.slots_mac,
    };
  }

  return null;
}
