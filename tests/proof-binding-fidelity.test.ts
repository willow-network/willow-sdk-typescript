/**
 * Document/value binding hardening (proof/index.ts).
 *
 * The proven Item bytes are authoritative; a returned document must bind to the
 * JSON those bytes decode to. We mock the GroveDB verifier so each test can pin
 * the exact proven byte sequence, then assert the binding rejects collisions a
 * naive JS-value deep-equal would accept (big-int precision drift, -0 vs 0,
 * NaN), binds JSON null correctly, handles non-JSON Item bytes by exact bytes,
 * and is not fooled by __proto__/constructor keys.
 */

import type { GroveDBVerificationResult } from '../src/grovedb';

const ROOT_HEX = 'ab'.repeat(32);

jest.mock('../src/grovedb', () => {
  const actual = jest.requireActual('../src/grovedb');
  return {
    ...actual,
    hexToBytes: jest.fn(() => new Uint8Array([1])), // non-empty so decodeProofBytes passes
    hashToHex: jest.fn(() => ROOT_HEX),
    quickVerify: jest.fn(() => new Uint8Array(32)),
    verifyGroveDBProof: jest.fn(),
  };
});

import { verifyGroveDBProof } from '../src/grovedb';
import { verifyQueryProof, verifyItemProof } from '../src/proof';

const mockVerify = verifyGroveDBProof as jest.MockedFunction<typeof verifyGroveDBProof>;

/** A verification result with one proven Item whose bytes are `text`. */
function provenItem(text: string, key = 'k', pathSegments: string[] = []): GroveDBVerificationResult {
  const enc = new TextEncoder();
  return {
    rootHash: new Uint8Array(32),
    results: [
      {
        path: pathSegments.map((p) => enc.encode(p)),
        key: enc.encode(key),
        value: enc.encode(text),
        element: { type: 'Item', value: enc.encode(text), flags: null } as any,
      },
    ],
  } as GroveDBVerificationResult;
}

/** A verification result with one proven Item whose bytes are raw (non-JSON). */
function provenRawItem(bytes: Uint8Array, key = 'k'): GroveDBVerificationResult {
  return {
    rootHash: new Uint8Array(32),
    results: [
      {
        path: [],
        key: new TextEncoder().encode(key),
        value: bytes,
        element: { type: 'Item', value: bytes, flags: null } as any,
      },
    ],
  } as GroveDBVerificationResult;
}

beforeEach(() => jest.clearAllMocks());

describe('verifyQueryProof — number-fidelity binding', () => {
  it('rejects a big-int precision collision (proven 2^53, server sent 2^53+1)', async () => {
    // Both 9007199254740992 and 9007199254740993 JSON.parse to 2^53; a naive
    // deep-equal would bind the server's distinct value. Reject it.
    mockVerify.mockReturnValue(provenItem('{"n":9007199254740992}'));
    await expect(
      verifyQueryProof('00', [{ n: 9007199254740993 } as any]),
    ).rejects.toThrow(/not committed by the proof/);
  });

  it('rejects an unsafe integer even against an identical JS value (no false bind)', async () => {
    mockVerify.mockReturnValue(provenItem('{"n":9007199254740992}'));
    await expect(
      verifyQueryProof('00', [{ n: 9007199254740992 } as any]),
    ).rejects.toThrow(/not committed by the proof/);
  });

  it('binds a safe-integer document', async () => {
    mockVerify.mockReturnValue(provenItem('{"n":42}'));
    await expect(verifyQueryProof('00', [{ n: 42 } as any])).resolves.toBe(ROOT_HEX);
  });

  it('rejects -0 against proven 0', async () => {
    mockVerify.mockReturnValue(provenItem('{"x":0}'));
    await expect(
      verifyQueryProof('00', [{ x: -0 } as any]),
    ).rejects.toThrow(/not committed by the proof/);
  });

  it('rejects NaN (never a legal JSON literal anyway)', async () => {
    mockVerify.mockReturnValue(provenItem('{"x":0}'));
    await expect(
      verifyQueryProof('00', [{ x: NaN } as any]),
    ).rejects.toThrow(/not committed by the proof/);
  });

  it('binds finite non-integers that round-trip (e.g. 1.5)', async () => {
    mockVerify.mockReturnValue(provenItem('{"x":1.5}'));
    await expect(verifyQueryProof('00', [{ x: 1.5 } as any])).resolves.toBe(ROOT_HEX);
  });
});

describe('verifyQueryProof — prototype pollution safety', () => {
  it('is not fooled by a __proto__ key in the server document', async () => {
    mockVerify.mockReturnValue(provenItem('{"a":1}'));
    const malicious = JSON.parse('{"a":1,"__proto__":{"x":1}}');
    await expect(
      verifyQueryProof('00', [malicious]),
    ).rejects.toThrow(/not committed by the proof/);
    // The comparison must not have polluted Object.prototype.
    expect(({} as any).x).toBeUndefined();
  });

  it('does not bind a document with an extra inherited-looking constructor key', async () => {
    mockVerify.mockReturnValue(provenItem('{"a":1}'));
    const doc = JSON.parse('{"a":1,"constructor":"evil"}');
    await expect(verifyQueryProof('00', [doc])).rejects.toThrow(/not committed/);
  });
});

describe('verifyItemProof — null and non-JSON Item bytes', () => {
  it('binds a proven JSON null to a null value', async () => {
    mockVerify.mockReturnValue(provenItem('null'));
    await expect(verifyItemProof('00', 'k', null)).resolves.toBe(ROOT_HEX);
  });

  it('rejects a non-null value when the proof commits to null', async () => {
    mockVerify.mockReturnValue(provenItem('null'));
    await expect(
      verifyItemProof('00', 'k', { not: 'null' }),
    ).rejects.toThrow(/does not match the returned data/);
  });

  it('rejects a null value when the proof commits to a non-null document', async () => {
    mockVerify.mockReturnValue(provenItem('{"a":1}'));
    await expect(
      verifyItemProof('00', 'k', null),
    ).rejects.toThrow(/does not match the returned data/);
  });

  it('binds a non-JSON (raw bytes) Item to an exact-bytes value', async () => {
    const raw = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    mockVerify.mockReturnValue(provenRawItem(raw));
    await expect(verifyItemProof('00', 'k', new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).resolves.toBe(
      ROOT_HEX,
    );
  });

  it('rejects a non-JSON Item against differing bytes', async () => {
    const raw = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    mockVerify.mockReturnValue(provenRawItem(raw));
    await expect(
      verifyItemProof('00', 'k', new Uint8Array([0x00, 0x01])),
    ).rejects.toThrow(/does not match the returned data/);
  });

  it('skips value binding (checks only key/path/root) when value is undefined', async () => {
    mockVerify.mockReturnValue(provenItem('{"a":1}'));
    await expect(verifyItemProof('00', 'k', undefined)).resolves.toBe(ROOT_HEX);
  });
});
