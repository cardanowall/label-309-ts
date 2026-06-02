// Canonical wire-form serializer for VerifyReport. The TS and Python SDKs must
// emit byte-identical JSON for the same report so cross-language fixtures stay
// in lockstep; the byte-to-hex encoding and the undefined/null-omission rules
// below are the contract that guarantees that.
//
// Since the SDK's `VerifyReport` type IS the wire shape (snake_case keys),
// this helper exists only to normalise non-JSON-native values:
//   * `Uint8Array` → lowercase hex (no `0x` prefix).
//   * `undefined` / `null` values are OMITTED.
//   * `Map` is rejected — the wire format does not allow it and any stray
//     instance points at an internal bug, not a data shape we should silently
//     serialise.

import { bytesToHex } from '../hex';
import type { VerifyReport } from './types';

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object') return false;
  if (Array.isArray(v) || v instanceof Uint8Array || v instanceof Map || v instanceof Set) {
    return false;
  }
  return true;
}

function walk(value: unknown): unknown {
  if (value === undefined || value === null) return undefined;
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (value instanceof Map) {
    throw new Error('unsupported Map in VerifyReport tree');
  }
  if (Array.isArray(value)) {
    return value.map((v) => walk(v));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined || v === null) continue;
      const walked = walk(v);
      if (walked === undefined) continue;
      out[k] = walked;
    }
    return out;
  }
  return value;
}

export function verifyReportToDict(report: VerifyReport): Record<string, unknown> {
  const out = walk(report);
  if (!isPlainObject(out)) {
    throw new Error('verifyReportToDict: walk produced non-object root');
  }
  return out;
}
