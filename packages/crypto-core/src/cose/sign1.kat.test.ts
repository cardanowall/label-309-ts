import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { signEd25519 } from '../sig/ed25519';

import {
  CARDANO_POE_SIG_DOMAIN_PREFIX,
  buildLabel309SigStructure,
  buildSigStructure,
  coseSign1Label309Build,
  coseSign1Label309Verify,
  type CoseHeader,
} from './sign1';

interface CardanoPoeBuildVector {
  name: string;
  source: string;
  signer_secret_key_hex: string;
  signer_public_key_hex: string;
  protected_header_int_int_pairs: Array<[number, number]>;
  protected_header_int_bytes_pairs: Array<[number, string]>;
  unprotected_header_int_bytes_pairs: Array<[number, string]>;
  record_body_cbor_hex: string;
  expected_sig_structure_hex: string;
  expected_signature_hex: string;
  expected_cose_sign1_hex: string;
  // Optional, present on vectors authored ≥ (chunked + sigs[]).
  expected_cose_sign1_chunks_hex?: string[];
  expected_sigs_entry_cbor_hex?: string;
}

interface Sign1BuildCorpus {
  version: number;
  primitive: string;
  source: string;
  cardano_poe_vectors: CardanoPoeBuildVector[];
}

interface SigStructureVector {
  name: string;
  context: 'Signature1';
  body_protected_bytes_hex: string;
  external_aad_hex: string;
  payload_hex: string;
  expected_sig_structure_hex: string;
}

interface SigStructureCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: SigStructureVector[];
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

const here = path.dirname(fileURLToPath(import.meta.url));
const buildFixturePath = path.resolve(here, '../../tests/fixtures/cose/sign1-build.json');
const sigStructureFixturePath = path.resolve(here, '../../tests/fixtures/cose/sig-structure.json');
const buildCorpus = JSON.parse(fs.readFileSync(buildFixturePath, 'utf8')) as Sign1BuildCorpus;
const sigStructureCorpus = JSON.parse(
  fs.readFileSync(sigStructureFixturePath, 'utf8'),
) as SigStructureCorpus;

describe('cose-sign1 — domain-prefix constant', () => {
  it('is exactly the spec-pinned 25-byte UTF-8 string', () => {
    expect(CARDANO_POE_SIG_DOMAIN_PREFIX).toBe('cardano-poe-record-sig-v1');
    const bytes = new TextEncoder().encode(CARDANO_POE_SIG_DOMAIN_PREFIX);
    expect(bytes.length).toBe(25);
    // Verify the byte-pinned UTF-8 hex of the domain prefix.
    expect(bytesToHex(bytes)).toBe('63617264616e6f2d706f652d7265636f72642d7369672d7631');
  });
});

describe('cose-sign1 — Sig_structure build vectors', () => {
  for (const vector of sigStructureCorpus.vectors) {
    it(`builds byte-identical Sig_structure for ${vector.name}`, () => {
      const result = buildSigStructure({
        context: vector.context,
        bodyProtectedBytes: hexToBytes(vector.body_protected_bytes_hex),
        externalAad: hexToBytes(vector.external_aad_hex),
        payload: hexToBytes(vector.payload_hex),
      });
      expect(bytesToHex(result)).toBe(vector.expected_sig_structure_hex);
    });
  }
});

describe('cose-sign1 — Label 309 production vectors', () => {
  for (const vector of buildCorpus.cardano_poe_vectors) {
    it(`builds byte-identical Sig_structure via buildLabel309SigStructure for ${vector.name}`, () => {
      // Reconstruct the protected_bytes the builder will emit by hand-encoding
      // the {1: -8, 4: <pub>} map. The reference vector pins it as
      // a201270458203d4017c3...4660c (38 bytes).
      const protectedHeader = new Map<number | string, unknown>([
        ...vector.protected_header_int_int_pairs.map(([k, v]) => [k, v] as [number, number]),
        ...vector.protected_header_int_bytes_pairs.map(
          ([k, vHex]) => [k, hexToBytes(vHex)] as [number, Uint8Array],
        ),
      ]);
      // Reuse the production builder so we exercise the public surface end-to-end.
      const cose = coseSign1Label309Build({
        protectedHeader,
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
        signerSecretKey: hexToBytes(vector.signer_secret_key_hex),
      });
      expect(bytesToHex(cose)).toBe(vector.expected_cose_sign1_hex);
    });

    it(`buildLabel309SigStructure emits the spec-pinned Sig_structure for ${vector.name}`, () => {
      // Each Label 309 path-1 vector encodes protected = {1: -8, 4: <32B pub>},
      // whose canonical CBOR is the 38-byte prefix `a2 01 27 04 58 20 || <pub>`.
      // Build that hex per-vector so this test covers the reference vector
      // AND every fixture (which use distinct public keys).
      const protectedHex = `a201270458 20 ${vector.signer_public_key_hex}`.replace(/\s+/g, '');
      const sigStructureBytes = buildLabel309SigStructure({
        bodyProtectedBytes: hexToBytes(protectedHex),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
      });
      expect(bytesToHex(sigStructureBytes)).toBe(vector.expected_sig_structure_hex);
    });

    it(`buildLabel309SigStructure forces external_aad = h'' regardless of input bytes for ${vector.name}`, () => {
      // The helper does not accept an externalAad arg; assert that the produced
      // Sig_structure pins index-2 to a zero-length bstr (CBOR 0x40). The
      // protected_bytes for {1:-8, 4:<pub>} is always 38 bytes, so the layout is:
      // [0]=84 (array(4)), [1..11]="Signature1" (11 B), [12]=58, [13]=26,
      // [14..51]=protected (38 B), [52]=0x40 expected.
      const protectedHex = `a201270458 20 ${vector.signer_public_key_hex}`.replace(/\s+/g, '');
      const sigStructureBytes = buildLabel309SigStructure({
        bodyProtectedBytes: hexToBytes(protectedHex),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
      });
      expect(sigStructureBytes[52]).toBe(0x40);
    });
  }
});

describe('cose-sign1 — Label 309 verify (round-trip)', () => {
  for (const vector of buildCorpus.cardano_poe_vectors) {
    it(`coseSign1Label309Verify accepts the spec-pinned message for ${vector.name}`, () => {
      const result = coseSign1Label309Verify({
        message: hexToBytes(vector.expected_cose_sign1_hex),
        detachedRecordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(bytesToHex(result.signerKey)).toBe(vector.signer_public_key_hex);
        expect(result.alg).toBe(-8);
      }
    });

    it(`coseSign1Label309Verify rejects a body mutation as SIGNATURE_INVALID for ${vector.name}`, () => {
      const mutatedBody = hexToBytes(vector.record_body_cbor_hex);
      // Flip the last byte (semantically alters the blake2b hash digest).
      mutatedBody[mutatedBody.length - 1] = (mutatedBody[mutatedBody.length - 1] ?? 0) ^ 0xff;
      const result = coseSign1Label309Verify({
        message: hexToBytes(vector.expected_cose_sign1_hex),
        detachedRecordBodyCbor: mutatedBody,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('SIGNATURE_INVALID');
    });
  }
});

// Sig_structure + signature byte-pin parity for the new vectors.
describe('cose-sign1 — Label 309 production vectors', () => {
  // The fixture vector ids use the `label309-` prefix, frozen byte-for-byte in
  // the cross-SDK corpus, so this filter literal must match it exactly.
  const label309Vectors = buildCorpus.cardano_poe_vectors.filter((v) =>
    v.name.startsWith('label309-'),
  );

  it('corpus contains at least 3 Label 309 vectors (cross-SDK parity gate)', () => {
    expect(label309Vectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const vector of label309Vectors) {
    it(`Sig_structure bytes match KAT for ${vector.name}`, () => {
      // {1: -8, 4: <pub>} canonical CBOR = a2 01 27 04 58 20 <32B>.
      const protectedHex = `a201270458 20 ${vector.signer_public_key_hex}`.replace(/\s+/g, '');
      const sigStructureBytes = buildLabel309SigStructure({
        bodyProtectedBytes: hexToBytes(protectedHex),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
      });
      expect(bytesToHex(sigStructureBytes)).toBe(vector.expected_sig_structure_hex);
    });

    it(`signature bytes match KAT (Ed25519 strict) for ${vector.name}`, () => {
      const cose = coseSign1Label309Build({
        protectedHeader: new Map<number | string, unknown>([
          ...vector.protected_header_int_int_pairs.map(([k, v]) => [k, v] as [number, number]),
          ...vector.protected_header_int_bytes_pairs.map(
            ([k, vHex]) => [k, hexToBytes(vHex)] as [number, Uint8Array],
          ),
        ]),
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
        signerSecretKey: hexToBytes(vector.signer_secret_key_hex),
      });
      // The signature occupies the last 64 bytes of the COSE_Sign1 array's
      // 4th element. Easier to compare the entire cose hex which embeds it.
      expect(bytesToHex(cose)).toBe(vector.expected_cose_sign1_hex);
    });

    it(`signer-closure path produces byte-identical output for ${vector.name}`, () => {
      // The closure receives the pre-computed Sig_structure bytes and returns
      // the 64-byte signature. Composer-side code uses this path so the raw
      // seed never escapes the unlock-store closure.
      const captured: Uint8Array[] = [];
      const seed = hexToBytes(vector.signer_secret_key_hex);
      const cose = coseSign1Label309Build({
        protectedHeader: new Map<number | string, unknown>([
          ...vector.protected_header_int_int_pairs.map(([k, v]) => [k, v] as [number, number]),
          ...vector.protected_header_int_bytes_pairs.map(
            ([k, vHex]) => [k, hexToBytes(vHex)] as [number, Uint8Array],
          ),
        ]),
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
        signer: (sigStructureBytes) => {
          captured.push(sigStructureBytes);
          return signEd25519({ seed, message: sigStructureBytes });
        },
      });
      expect(bytesToHex(cose)).toBe(vector.expected_cose_sign1_hex);
      expect(captured.length).toBe(1);
      expect(bytesToHex(captured[0]!)).toBe(vector.expected_sig_structure_hex);
    });
  }
});

describe('cose-sign1 — CoseSign1BuildError', () => {
  const vector = buildCorpus.cardano_poe_vectors.find((v) => v.name.startsWith('label309-'))!;
  const baseHeader = (): CoseHeader =>
    new Map<number | string, unknown>([
      ...vector.protected_header_int_int_pairs.map(([k, v]) => [k, v] as [number, number]),
      ...vector.protected_header_int_bytes_pairs.map(
        ([k, vHex]) => [k, hexToBytes(vHex)] as [number, Uint8Array],
      ),
    ]);

  it('throws SIGNER_NOT_PROVIDED when neither seed nor closure supplied', () => {
    expect(() =>
      coseSign1Label309Build({
        protectedHeader: baseHeader(),
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
      }),
    ).toThrowError(
      expect.objectContaining({ name: 'CoseSign1BuildError', code: 'SIGNER_NOT_PROVIDED' }),
    );
  });

  it('throws SIGNER_AND_SEED_BOTH_PROVIDED when both are supplied', () => {
    expect(() =>
      coseSign1Label309Build({
        protectedHeader: baseHeader(),
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
        signerSecretKey: hexToBytes(vector.signer_secret_key_hex),
        signer: () => new Uint8Array(64),
      }),
    ).toThrowError(
      expect.objectContaining({
        name: 'CoseSign1BuildError',
        code: 'SIGNER_AND_SEED_BOTH_PROVIDED',
      }),
    );
  });

  it('rejects a closure that returns a non-64-byte value', () => {
    expect(() =>
      coseSign1Label309Build({
        protectedHeader: baseHeader(),
        unprotectedHeader: new Map(),
        recordBodyCbor: hexToBytes(vector.record_body_cbor_hex),
        signer: () => new Uint8Array(63),
      }),
    ).toThrowError(
      expect.objectContaining({ name: 'CoseSign1BuildError', code: 'SIGNER_NOT_PROVIDED' }),
    );
  });
});
