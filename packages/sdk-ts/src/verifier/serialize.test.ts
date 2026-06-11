import { describe, expect, it } from 'vitest';

import { verifyReportToDict } from './serialize';
import type { VerifyReport } from './types';

function mkReport(): VerifyReport {
  return {
    verdict: 'valid',
    exitCode: 0,
    issues: [],
    items: [{ contentCheck: 'checked' }],
    merkle: [],
    auditTrail: [
      {
        url: 'https://example.com',
        method: 'GET',
        status: 200,
        bytes: 10,
        durationMs: 5,
        purpose: 'cardano',
      },
    ],
    network: 'cardano:mainnet',
    confirmationDepth: 42,
    confirmationThreshold: 15,
    block_time: 1700000000,
    txHash: 'abc',
    profile: 'recipient-sealed',
  };
}

describe('verifyReportToDict', () => {
  it('is deterministic across calls', () => {
    const r = mkReport();
    expect(JSON.stringify(verifyReportToDict(r))).toBe(JSON.stringify(verifyReportToDict(r)));
  });

  it('omits undefined/null values everywhere except the required audit-entry status', () => {
    const report: VerifyReport = {
      ...mkReport(),
      auditTrail: [
        {
          url: 'https://example.com',
          method: 'GET',
          status: null,
          bytes: 0,
          durationMs: 0,
          purpose: 'cardano',
        },
      ],
    };
    const d = verifyReportToDict(report);
    // The schema requires `status` on every audit entry, with null as the
    // no-response reading: a transport failure serialises as JSON null.
    const trail = d['auditTrail'] as Array<Record<string, unknown>>;
    expect(trail).toHaveLength(1);
    expect('status' in trail[0]!).toBe(true);
    expect(trail[0]!['status']).toBeNull();
    // Everywhere else, null/undefined values are omitted.
    function walk(value: unknown): void {
      if (Array.isArray(value)) {
        for (const item of value) walk(item);
        return;
      }
      if (value && typeof value === 'object') {
        for (const v of Object.values(value as Record<string, unknown>)) {
          expect(v).not.toBeNull();
          expect(v).not.toBeUndefined();
          walk(v);
        }
      }
    }
    const { auditTrail: _trail, ...rest } = d;
    walk(rest);
    expect('block_slot' in d).toBe(false);
  });

  it('renders bytes as lowercase hex without 0x prefix', () => {
    const bytes = new Uint8Array([0x00, 0xab, 0xff, 0x10]);
    const report: VerifyReport = {
      ...mkReport(),
      record: {
        v: 1,
        items: [{ hashes: { 'sha2-256': bytes as Uint8Array<ArrayBuffer> } }],
      },
    };
    const d = verifyReportToDict(report);
    const rec = d['record'] as Record<string, unknown>;
    const items = rec['items'] as Array<Record<string, unknown>>;
    const hashes = items[0]!['hashes'] as Record<string, unknown>;
    expect(hashes['sha2-256']).toBe('00abff10');
  });

  it('rejects a stray Map in the report tree', () => {
    const report = {
      ...mkReport(),
      record: new Map([['v', 1]]),
    } as unknown as VerifyReport;
    expect(() => verifyReportToDict(report)).toThrowError(/Map/);
  });
});
