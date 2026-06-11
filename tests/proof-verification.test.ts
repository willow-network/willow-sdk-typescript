/**
 * Tests for the proof verification helpers in src/proof/index.ts.
 *
 * The core "does the verifier actually verify" behavior is covered by
 * tests/proof-wiring.test.ts. This file covers the wrappers around it —
 * structured results, expected-root enforcement — and the document/value
 * binding that ties returned data to what the proof commits to.
 */

import * as fs from 'fs';
import * as path from 'path';

import {
  verifyProofAdvanced,
  verifyQueryResponse,
  verifyItemProof,
  verifyQueryProof,
  computeProofRootHash,
  extractRootHashFromProof,
  GroveDBProofVerifier,
} from '../src/proof';
import { verifyGroveDBProof, hexToBytes } from '../src/grovedb';
import { QueryResponse } from '../src/types';

function highEntropyHex(length: number, offset = 0): string {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (offset + i * 17 + 29) & 0xff;
  return Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('');
}

const fx = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', 'partial-proof-live.json'), 'utf8'),
) as { proofHex: string; stateRootHex: string };

/** The JSON document the live fixture's proof actually commits to. */
function fixtureDocument(): Record<string, unknown> {
  const { results } = verifyGroveDBProof(hexToBytes(fx.proofHex));
  const item = results.find((r) => r.element?.type === 'Item');
  if (!item || item.element?.type !== 'Item') throw new Error('fixture has no Item');
  return JSON.parse(new TextDecoder().decode(item.element.value));
}

describe('document binding — returned data must be committed by the proof', () => {
  it('accepts documents the proof commits to', async () => {
    const doc = fixtureDocument();
    const root = await verifyQueryProof(fx.proofHex, [doc]);
    expect(root.toLowerCase()).toBe(fx.stateRootHex.replace(/^0x/, '').toLowerCase());
  });

  it('rejects a valid proof paired with documents it does not commit to', async () => {
    const tampered = { ...fixtureDocument(), assets: '999999999999' };
    await expect(verifyQueryProof(fx.proofHex, [tampered])).rejects.toThrow(
      /not committed by the proof/,
    );
  });

  it('rejects when any one of several documents is unbound', async () => {
    const doc = fixtureDocument();
    await expect(
      verifyQueryProof(fx.proofHex, [doc, { fabricated: true }]),
    ).rejects.toThrow(/index 1/);
  });

  it('still verifies the proof itself when no documents are supplied', async () => {
    const root = await verifyQueryProof(fx.proofHex, []);
    expect(root.toLowerCase()).toBe(fx.stateRootHex.replace(/^0x/, '').toLowerCase());
  });
});

describe('item value binding', () => {
  it('rejects a proven key paired with a value the proof does not commit to', async () => {
    const { results } = verifyGroveDBProof(hexToBytes(fx.proofHex));
    const item = results.find((r) => r.element?.type === 'Item')!;
    const key = new TextDecoder().decode(item.key);
    const pathSegments = item.path.map((p) => new TextDecoder().decode(p));

    const doc = fixtureDocument();
    await expect(
      verifyItemProof(fx.proofHex, key, doc, pathSegments),
    ).resolves.toBeTruthy();

    await expect(
      verifyItemProof(fx.proofHex, key, { ...doc, assets: '0' }, pathSegments),
    ).rejects.toThrow(/does not match the returned data/);
  });
});

describe('verifyProofAdvanced (deprecated wrapper)', () => {
  it('returns { valid: false, error } for invalid proofs instead of throwing', async () => {
    const result = await verifyProofAdvanced(highEntropyHex(128), [{ key: 'k', value: 'v' }]);
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('returns { valid: false, error } for empty proof', async () => {
    const result = await verifyProofAdvanced('', []);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Empty proof');
  });

  it('returns { valid: false, error } for invalid hex', async () => {
    const result = await verifyProofAdvanced('nothex', []);
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe('GroveDBProofVerifier — instance-scoped options', () => {
  it('enforces expectedRootHash from instance options', async () => {
    const wrong = new GroveDBProofVerifier({ expectedRootHash: 'a'.repeat(64) });
    const result = await wrong.verifyQueryProof(fx.proofHex, []);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Root hash mismatch/);

    const right = new GroveDBProofVerifier({ expectedRootHash: fx.stateRootHex });
    const ok = await right.verifyQueryProof(fx.proofHex, []);
    expect(ok.valid).toBe(true);
  });
});

describe('verifyQueryResponse', () => {
  it('throws when response has no proof', async () => {
    const response = { documents: [], proof: undefined } as unknown as QueryResponse;
    await expect(verifyQueryResponse(response)).rejects.toThrow(/does not contain proof/);
  });

  it('delegates to verifyQueryProof for responses with a proof', async () => {
    const response = {
      documents: [],
      proof: highEntropyHex(128),
    } as unknown as QueryResponse;
    await expect(verifyQueryResponse(response)).rejects.toThrow();
  });
});

describe('computeProofRootHash', () => {
  it('fully verifies — garbage is rejected, the fixture verifies', async () => {
    await expect(computeProofRootHash(highEntropyHex(128))).rejects.toThrow();
    const root = await computeProofRootHash(fx.proofHex);
    expect(root.toLowerCase()).toBe(fx.stateRootHex.replace(/^0x/, '').toLowerCase());
  });

  it('keeps the deprecated extractRootHashFromProof alias working', async () => {
    expect(extractRootHashFromProof).toBe(computeProofRootHash);
  });
});
