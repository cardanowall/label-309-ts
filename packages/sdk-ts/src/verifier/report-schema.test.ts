// Emitted reports against the published verify-report JSON Schema.
//
// The schema's load-bearing invariants are read from the schema document
// itself (committed local test data, mirrored from the standard's corpus) and
// asserted over reports the real pipeline emitted, one per verdict:
//
//   * the required top-level key set;
//   * the verdict enum and the verdict → exitCode constants;
//   * the valid-verdict severity rule (every issue carries an explicit
//     non-error severity, since an omitted severity defaults to error);
//   * the chain facts required for valid/pending outcomes;
//   * per-claim contentCheck values and the audit-entry required keys.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@cardanowall/crypto-core/hash';
import { encodePoeRecord, PoeRecordSchema } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { verifyReportToDict } from './serialize';
import type { VerifyReport } from './types';
import { verifyResolved } from './verify';

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.resolve(here, '../../tests/fixtures/verify-report.schema.json');

interface ReportSchema {
  required: string[];
  properties: {
    verdict: { enum: string[] };
    exitCode: { enum: number[] };
  };
  allOf: Array<{
    if: { properties: { verdict: { const?: string; enum?: string[] } } };
    then: {
      properties?: { exitCode?: { const: number } };
      required?: string[];
    };
  }>;
  $defs: {
    'content-check': { enum: string[] };
    'audit-entry': { required: string[] };
    issue: { required: string[] };
  };
}

const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8')) as ReportSchema;

function exitCodeConstFor(verdict: string): number | undefined {
  for (const rule of schema.allOf) {
    if (rule.if.properties.verdict.const === verdict) {
      return rule.then.properties?.exitCode?.const;
    }
  }
  return undefined;
}

function assertSchemaInvariants(report: VerifyReport): void {
  const dict = verifyReportToDict(report);

  // Required top-level keys, straight from the schema document.
  for (const key of schema.required) {
    expect(dict, `missing required report key "${key}"`).toHaveProperty(key);
  }

  // Verdict enum + the verdict → exitCode constants.
  expect(schema.properties.verdict.enum).toContain(report.verdict);
  expect(schema.properties.exitCode.enum).toContain(report.exitCode);
  expect(report.exitCode).toBe(exitCodeConstFor(report.verdict));

  // Chain facts required for valid/pending verdicts.
  if (report.verdict === 'valid' || report.verdict === 'pending') {
    const chainRule = schema.allOf.find((r) => r.if.properties.verdict.enum !== undefined);
    for (const key of chainRule?.then.required ?? []) {
      expect(
        dict,
        `missing chain-fact key "${key}" under verdict ${report.verdict}`,
      ).toHaveProperty(key);
    }
  }

  // The severity contract under a valid verdict.
  if (report.verdict === 'valid') {
    for (const issue of report.issues) {
      expect(issue.severity === 'warning' || issue.severity === 'info').toBe(true);
    }
  }

  // Issue shape.
  for (const issue of report.issues) {
    for (const key of schema.$defs.issue.required) {
      expect(issue).toHaveProperty(key);
    }
    expect(issue.code).toMatch(/^[A-Z][A-Z0-9_]*$/);
  }

  // Per-claim content-check values.
  const contentChecks = schema.$defs['content-check'].enum;
  for (const entry of report.items) expect(contentChecks).toContain(entry.contentCheck);
  for (const entry of report.merkle) expect(contentChecks).toContain(entry.contentCheck);

  // Audit-entry required keys.
  for (const call of report.auditTrail) {
    for (const key of schema.$defs['audit-entry'].required) {
      expect(call).toHaveProperty(key);
    }
  }
}

const record = PoeRecordSchema.parse({
  v: 1,
  items: [{ hashes: { 'sha2-256': sha256(new TextEncoder().encode('schema test')) } }],
});
const recordBody = encodePoeRecord(record);

describe('emitted reports conform to the verify-report schema invariants', () => {
  it('valid verdict', async () => {
    const r = await verifyResolved({
      txHash: '0'.repeat(64),
      metadataCbor: recordBody,
      confirmationDepth: 42,
      blockTime: 1700000000,
      fetchContent: false,
    });
    expect(r.verdict).toBe('valid');
    assertSchemaInvariants(r);
  });

  it('pending verdict', async () => {
    const r = await verifyResolved({
      txHash: '0'.repeat(64),
      metadataCbor: recordBody,
      confirmationDepth: 1,
      blockTime: 1700000000,
      fetchContent: false,
    });
    expect(r.verdict).toBe('pending');
    assertSchemaInvariants(r);
  });

  it('failed verdict (structural rejection)', async () => {
    const r = await verifyResolved({
      txHash: '0'.repeat(64),
      metadataCbor: new TextEncoder().encode('not a record'),
      confirmationDepth: 42,
      blockTime: 1700000000,
      fetchContent: false,
    });
    expect(r.verdict).toBe('failed');
    assertSchemaInvariants(r);
  });

  it('unverifiable verdict (content unavailable)', async () => {
    const withUri = PoeRecordSchema.parse({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': sha256(new TextEncoder().encode('schema test')) },
          uris: ['ar://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
        },
      ],
    });
    const r = await verifyResolved({
      txHash: '0'.repeat(64),
      metadataCbor: encodePoeRecord(withUri),
      confirmationDepth: 42,
      blockTime: 1700000000,
      fetchOutbound: async () => ({ status: 500, bytes: new Uint8Array(0), durationMs: 1 }),
    });
    expect(r.verdict).toBe('unverifiable');
    assertSchemaInvariants(r);
  });
});
