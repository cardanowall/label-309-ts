// Unit tests for detectConformanceProfile.

import type { PoeRecord } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { detectConformanceProfile } from './profile';

function baseRecord(): PoeRecord {
  return {
    cw_version: 1,
    chain: 'cardano:mainnet',
    iat: '2026-01-01T00:00:00.000Z',
    items: [{ item_idx: 0, hashes: { 'sha2-256': new Uint8Array(32) } }],
  } as unknown as PoeRecord;
}

describe('detectConformanceProfile', () => {
  it('returns "core" for a hash-only record', () => {
    expect(detectConformanceProfile(baseRecord())).toBe('core');
  });

  it('returns "signed" when sigs[] is non-empty and no enc', () => {
    const rec = {
      ...baseRecord(),
      sigs: [{ cose_sign1: new Uint8Array(64) }],
    } as unknown as PoeRecord;
    expect(detectConformanceProfile(rec)).toBe('signed');
  });

  it('returns "core" when sigs[] is an empty array', () => {
    const rec = { ...baseRecord(), sigs: [] } as unknown as PoeRecord;
    expect(detectConformanceProfile(rec)).toBe('core');
  });

  it('returns "sealed" when any item has enc', () => {
    const rec = baseRecord();
    (rec.items as unknown as Array<Record<string, unknown>>)[0] = {
      item_idx: 0,
      hashes: { 'sha2-256': new Uint8Array(32) },
      enc: { scheme: 1 },
    };
    expect(detectConformanceProfile(rec)).toBe('sealed');
  });

  it('returns "sealed" when sigs AND enc are both present (sealed wins)', () => {
    const rec = baseRecord();
    (rec.items as unknown as Array<Record<string, unknown>>)[0] = {
      item_idx: 0,
      hashes: { 'sha2-256': new Uint8Array(32) },
      enc: { scheme: 1 },
    };
    (rec as unknown as { sigs: unknown }).sigs = [{ cose_sign1: new Uint8Array(64) }];
    expect(detectConformanceProfile(rec)).toBe('sealed');
  });

  it('returns "sealed" when only one of multiple items carries enc', () => {
    const rec: PoeRecord = {
      ...baseRecord(),
      items: [
        { item_idx: 0, hashes: { 'sha2-256': new Uint8Array(32) } },
        { item_idx: 1, hashes: { 'sha2-256': new Uint8Array(32) }, enc: { scheme: 1 } as never },
      ],
    } as unknown as PoeRecord;
    expect(detectConformanceProfile(rec)).toBe('sealed');
  });
});
