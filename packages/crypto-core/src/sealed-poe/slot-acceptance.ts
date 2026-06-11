// Per-slot acceptance accumulator for the trial-decrypt loop.
//
// A slot is "mine" only when its KEM validity bit, its wrap-open, AND its
// slot-set MAC check all hold (the folded per-slot `ok` bit). The accumulator
// selects the FIRST accepted slot's CEK, keeps scanning every remaining slot
// (the loop never breaks early within one private key's pass), and raises the
// conflict bit when a later accepted slot recovers a CEK that differs from the
// selected one — the multi-key commitment collision the construction fails
// closed on. Slots that wrap-open under an attacker-chosen CEK but fail the
// MAC are simply not accepted: they neither select a CEK nor raise a conflict,
// so an honest slot later in the array still wins.
//
// The fold is branchless mask-based selection — no control flow keyed on which
// slot matched:
//
//   first        = ok AND NOT found
//   cek_conflict = cek_conflict OR (ok AND found AND NOT ctEq(cand, selected))
//   selected_CEK = select(first, cand, selected)        (byte masks 0x00/0xFF)
//   selected_idx = select(first, idx, selected_idx)     (word masks 0/-1)
//   found        = found OR ok
//
// Every update runs on every slot with the same operations; the state is a
// fixed-size buffer plus 0|1 bits, never a data-dependent assignment guarded
// by `if`. JavaScript offers no hardware constant-time guarantee — a JIT may
// reintroduce data-dependent paths — so this is the best-effort discipline,
// not a timing proof.
//
// Two accepted slots recovering DIFFERENT CEKs requires a collision in the
// CEK-keyed commitment, so the conflict bit is not reachable through any
// envelope the public API can build; it is exercised directly on this
// accumulator. This module is internal to the trial-decrypt implementation and
// is not part of the package surface.

const CEK_LENGTH = 32;

// Mutable accumulator state. `foundBit` / `conflictBit` are 0|1 integers;
// `selectedCek` is a fixed 32-byte buffer (all-zero until a slot is accepted);
// `selectedSlotIdx` keeps the -1 sentinel until the first acceptance.
export interface SlotAcceptanceState {
  foundBit: number;
  conflictBit: number;
  readonly selectedCek: Uint8Array;
  selectedSlotIdx: number;
}

export function newSlotAcceptanceState(): SlotAcceptanceState {
  return {
    foundBit: 0,
    conflictBit: 0,
    selectedCek: new Uint8Array(CEK_LENGTH),
    selectedSlotIdx: -1,
  };
}

// Fold one slot's outcome into the state. `ok` MUST be the slot's
// `kem_ok AND open_ok AND mac_ok` acceptance as a 0|1 integer; `candidateCek`
// MUST be exactly 32 bytes (the recovered CEK, or the caller's fixed dummy
// when the wrap-open failed, so every slot folds the same-shaped input).
export function foldSlotAcceptance(
  state: SlotAcceptanceState,
  ok: number,
  candidateCek: Uint8Array,
  slotIdx: number,
): void {
  if (candidateCek.length !== CEK_LENGTH) {
    // Structural programmer-error guard on a public quantity (the wrap length
    // is wire-validated upstream); never reachable from envelope data.
    throw new Error(
      `candidate CEK MUST be exactly ${CEK_LENGTH} bytes, got ${candidateCek.length}`,
    );
  }
  const okBit = ok & 1;
  const firstBit = okBit & (state.foundBit ^ 1);
  const firstByteMask = -firstBit & 0xff; // 0x00 or 0xFF
  const firstWordMask = -firstBit | 0; // 0 or -1 (all-ones int32)

  // Constant-time inequality of candidate vs selected as a 0|1 bit. Computed
  // unconditionally on every slot; its conflict contribution is masked off
  // unless this slot AND an earlier slot were both accepted.
  let diff = 0;
  for (let i = 0; i < CEK_LENGTH; i++) {
    diff |= (candidateCek[i] as number) ^ (state.selectedCek[i] as number);
  }
  const neqBit = ((diff | -diff) >>> 31) & 1;

  state.conflictBit |= okBit & state.foundBit & neqBit;
  for (let i = 0; i < CEK_LENGTH; i++) {
    state.selectedCek[i] =
      ((candidateCek[i] as number) & firstByteMask) |
      ((state.selectedCek[i] as number) & ~firstByteMask & 0xff);
  }
  state.selectedSlotIdx = (slotIdx & firstWordMask) | (state.selectedSlotIdx & ~firstWordMask);
  state.foundBit |= okBit;
}

// The pass outcome in consumer shape, read once after the whole slot loop.
export interface SlotAcceptanceOutcome {
  readonly found: boolean;
  readonly cekConflict: boolean;
  // The first accepted slot's CEK (null when nothing was accepted).
  readonly selectedCek: Uint8Array | null;
  // The first accepted slot's index (-1 when nothing was accepted).
  readonly selectedSlotIdx: number;
}

export function finishSlotAcceptance(state: SlotAcceptanceState): SlotAcceptanceOutcome {
  const found = state.foundBit === 1;
  return {
    found,
    cekConflict: state.conflictBit === 1,
    selectedCek: found ? state.selectedCek : null,
    selectedSlotIdx: state.selectedSlotIdx,
  };
}
