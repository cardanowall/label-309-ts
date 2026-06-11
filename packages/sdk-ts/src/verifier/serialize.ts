// Canonical JSON-form serializer for VerifyReport. The report's property
// names already follow the published verify-report schema, so this helper
// exists only to normalise non-JSON-native values:
//   * `Uint8Array` → lowercase hex (no `0x` prefix).
//   * `undefined` / `null` values are OMITTED — except the audit-trail
//     `status`, which the published schema REQUIRES on every entry with null
//     as the no-response reading, so it serialises as JSON null.
//   * `Map` is rejected — the report shape does not allow it and any stray
//     instance points at an internal bug, not a data shape we should silently
//     serialise.

import { bytesToHex } from '../hex';
import type { HttpCallRecord, VerifyReport } from './types';

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

// Audit-trail entries carry a fixed schema-pinned shape; serialised
// explicitly so the required `status` key survives as JSON null when no HTTP
// response was received (the generic walk omits nulls).
function auditEntryToDict(call: HttpCallRecord): Record<string, unknown> {
  return {
    url: call.url,
    method: call.method,
    status: call.status,
    bytes: call.bytes,
    durationMs: call.durationMs,
    purpose: call.purpose,
  };
}

export function verifyReportToDict(report: VerifyReport): Record<string, unknown> {
  const out = walk(report);
  if (!isPlainObject(out)) {
    throw new Error('verifyReportToDict: walk produced non-object root');
  }
  out['auditTrail'] = report.auditTrail.map((call) => auditEntryToDict(call));
  return out;
}
