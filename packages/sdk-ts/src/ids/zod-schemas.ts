// Zod schema gating the Label 309 record id at every parse boundary (HTTP route
// handlers, SDK input validation, OpenAPI registration).
//
// The regex is the strict Crockford-32 alphabet (lowercase only on the wire,
// no I/L/O/U). This is stricter than `[0-9a-z]{26}` because it catches the
// most common typo classes (`poe_…ol1u…`) at the parser rather than letting
// them through to the decoder for a confusing `non-zero pad bits` error.

import { z } from 'zod';

const CROCKFORD_LOWER = '[0-9a-hjkmnp-tv-z]{26}';

export const POE_ID_PREFIX = 'poe' as const;

export const PoeIdSchema = z
  .string()
  .regex(new RegExp(`^${POE_ID_PREFIX}_${CROCKFORD_LOWER}$`), 'invalid poe id');

export const POE_ID_PATTERN = `^${POE_ID_PREFIX}_${CROCKFORD_LOWER}$`;
