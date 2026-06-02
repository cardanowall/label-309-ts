import { describe, expect, it } from 'vitest';

import { verifyReportToDict } from './serialize';
import type { VerifyReport } from './types';

function mkReport(): VerifyReport {
  return {
    tx_hash: 'abc',
    network: 'cardano:mainnet',
    profile: 'recipient-sealed',
    num_confirmations: 42,
    confirmation_depth_threshold: 15,
    block_time: 1700000000,
    metadata_present: true,
    validation: { valid: true },
    http_calls: [
      {
        url: 'https://example.com',
        method: 'GET',
        status: 200,
        bytes: 10,
        duration_ms: 5,
        purpose: 'cardano',
      },
    ],
    verdict: 'valid',
    exit_code: 0,
  };
}

function sortedKeys(_key: string, value: unknown): unknown {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
    );
  }
  return value;
}

describe('verifyReportToDict', () => {
  it('is deterministic across calls', () => {
    const r = mkReport();
    const d1 = verifyReportToDict(r);
    const d2 = verifyReportToDict(r);
    expect(JSON.stringify(d1, sortedKeys)).toBe(JSON.stringify(d2, sortedKeys));
  });

  it('emits snake_case keys, no nulls, no undefineds', () => {
    const d = verifyReportToDict(mkReport());
    function walk(value: unknown): void {
      if (Array.isArray(value)) {
        for (const item of value) walk(item);
        return;
      }
      if (value && typeof value === 'object') {
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          expect(k).toMatch(/^[a-z][a-z0-9_]*$/);
          expect(v).not.toBeNull();
          expect(v).not.toBeUndefined();
          walk(v);
        }
      }
    }
    walk(d);
  });

  it('renders bytes as lowercase hex without 0x prefix', () => {
    const bytes = new Uint8Array([0x00, 0xab, 0xff, 0x10]);
    const report: VerifyReport = {
      ...mkReport(),
      supersedes_resolved: { tx: '0'.repeat(64), exists: true },
      record: {
        v: 1,
        items: [{ hashes: { 'sha2-256': bytes } }],
      },
    };
    const d = verifyReportToDict(report);
    const rec = d['record'] as Record<string, unknown>;
    const items = rec['items'] as Array<Record<string, unknown>>;
    const hashes = items[0]!['hashes'] as Record<string, unknown>;
    expect(hashes['sha2-256']).toBe('00abff10');
  });

  it('matches the Python-canonical golden for a hand-rolled minimal report', () => {
    const report: VerifyReport = {
      tx_hash: 'abc',
      network: 'cardano:mainnet',
      profile: 'recipient-sealed',
      num_confirmations: 42,
      confirmation_depth_threshold: 15,
      block_time: 1700000000,
      metadata_present: true,
      validation: { valid: true },
      http_calls: [
        {
          url: 'https://example.com',
          method: 'GET',
          status: 200,
          bytes: 10,
          duration_ms: 5,
          purpose: 'cardano',
        },
      ],
      verdict: 'valid',
      exit_code: 0,
    };
    const actual = JSON.stringify(verifyReportToDict(report), sortedKeys, 2) + '\n';
    const golden =
      '{\n' +
      '  "block_time": 1700000000,\n' +
      '  "confirmation_depth_threshold": 15,\n' +
      '  "exit_code": 0,\n' +
      '  "http_calls": [\n' +
      '    {\n' +
      '      "bytes": 10,\n' +
      '      "duration_ms": 5,\n' +
      '      "method": "GET",\n' +
      '      "purpose": "cardano",\n' +
      '      "status": 200,\n' +
      '      "url": "https://example.com"\n' +
      '    }\n' +
      '  ],\n' +
      '  "metadata_present": true,\n' +
      '  "network": "cardano:mainnet",\n' +
      '  "num_confirmations": 42,\n' +
      '  "profile": "recipient-sealed",\n' +
      '  "tx_hash": "abc",\n' +
      '  "validation": {\n' +
      '    "valid": true\n' +
      '  },\n' +
      '  "verdict": "valid"\n' +
      '}\n';
    expect(actual).toBe(golden);
  });
});
