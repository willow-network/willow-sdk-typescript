/**
 * Tests for the proof verification helpers in src/proof/index.ts.
 *
 * The core "does the verifier actually verify" behavior is covered by
 * tests/proof-wiring.test.ts. This file covers the thin wrappers around it:
 * `configureProofVerification`, `verifyProofAdvanced`, `verifyQueryResponse`.
 */

import {
  configureProofVerification,
  verifyProofAdvanced,
  verifyQueryResponse,
  verifyItemProof,
  verifyQueryProof,
  extractRootHashFromProof,
} from '../src/proof';
import { QueryResponse } from '../src/types';

function highEntropyHex(length: number, offset = 0): string {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (offset + i * 17 + 29) & 0xff;
  return Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('verifyProofAdvanced', () => {
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

describe('verifyQueryResponse', () => {
  it('throws when response has no proof', async () => {
    const response = { documents: [], proof: undefined } as unknown as QueryResponse;
    await expect(verifyQueryResponse(response)).rejects.toThrow(
      /does not contain proof/,
    );
  });

  it('delegates to verifyQueryProof for responses with a proof', async () => {
    const response = {
      documents: [],
      proof: highEntropyHex(128),
    } as unknown as QueryResponse;
    await expect(verifyQueryResponse(response)).rejects.toThrow();
  });
});

describe('configureProofVerification — global expectedRootHash gate', () => {
  afterEach(() => {
    configureProofVerification({});
  });

  it('does not affect valid-proof rejection when no expectedRootHash is set', async () => {
    configureProofVerification({});
    await expect(verifyItemProof(highEntropyHex(128), 'k', 'v', [])).rejects.toThrow();
  });

  it('does not cause false positives — garbage still rejected even when expectedRootHash is set', async () => {
    configureProofVerification({
      expectedRootHash: 'a'.repeat(64),
    });
    await expect(verifyQueryProof(highEntropyHex(128), [])).rejects.toThrow();
    await expect(verifyItemProof(highEntropyHex(128), 'k', 'v', [])).rejects.toThrow();
    await expect(extractRootHashFromProof(highEntropyHex(128))).rejects.toThrow();
  });
});
