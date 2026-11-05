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
import { isExactJsonNumber, firstInexactNumber } from '../src/proof/shared';

const mockVerify = verifyGroveDBProof as jest.MockedFunction<typeof verifyGroveDBProof>;

/** A verification result with one proven Item whose bytes are `text`, as grovedb proves one (a KV node). */
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
        nodeType: 'KV',
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
        nodeType: 'KV',
      },
    ],
  } as GroveDBVerificationResult;
}

beforeEach(() => jest.clearAllMocks());

describe('verifyQueryProof — number-fidelity binding', () => {
  it('rejects a big-int precision collision (proven 2^53+1, which JSON.parse reads as 2^53)', async () => {
    // Both 9007199254740992 and 9007199254740993 JSON.parse to 2^53; a naive
    // deep-equal would bind 2^53 to the proven 2^53+1. Reject it.
    mockVerify.mockReturnValue(provenItem('{"n":9007199254740993}'));
    await expect(
      verifyQueryProof('00', [JSON.parse('{"n":9007199254740993}')]),
    ).rejects.toThrow(/not committed by the proof/);
    await expect(verifyItemProof('00', 'k', { n: 2 ** 53 })).rejects.toThrow(
      /holds the number 9007199254740993, which JavaScript can't carry exactly/,
    );
  });

  it('binds an integer beyond 2^53 - 1 whose digits are the ones JavaScript writes for its double', async () => {
    for (const n of [2 ** 53, 1e18, 2 ** 64, -(2 ** 60)]) {
      mockVerify.mockReturnValue(provenItem(JSON.stringify({ n })));
      await expect(verifyQueryProof('00', [{ n }])).resolves.toBe(ROOT_HEX);
      await expect(verifyItemProof('00', 'k', { n })).resolves.toBe(ROOT_HEX);
    }
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

describe('a number JavaScript cannot carry exactly never binds', () => {
  // 0.12345678901234567890 and 0.12345678901234568 parse to one double.
  const LONG = '0.12345678901234567890';

  it('a decimal whose double is written as another value, or that underflows', async () => {
    for (const text of [LONG, '1.0000000000000000001', '0.33333333333333331', '4.9406564584124654e-324', '1e-400']) {
      mockVerify.mockReturnValue(provenItem(`{"x":${text}}`));
      const value = JSON.parse(`{"x":${text}}`);
      await expect(verifyItemProof('00', 'k', value)).rejects.toThrow(
        new RegExp(`holds the number ${text.replace(/[.+-]/g, '\\$&')}, which JavaScript can't carry exactly`),
      );
      await expect(verifyQueryProof('00', [value])).rejects.toThrow(/not committed by the proof/);
    }
  });

  it('binds decimals of at most 15 significant digits, and digits in a string', async () => {
    for (const text of ['0.123456789012345', '1.5e-300', '-0.000001', '123456789.123456', '1.50000000000000000000']) {
      mockVerify.mockReturnValue(provenItem(`{"x":[${text}],"s":"${LONG}"}`));
      await expect(verifyItemProof('00', 'k', JSON.parse(`{"x":[${text}],"s":"${LONG}"}`))).resolves.toBe(ROOT_HEX);
    }
  });

  it('binds every number JavaScript writes, at 16 and 17 significant digits too', async () => {
    // What `client.store` sends for these values, and the API stores and returns.
    const written = [1.1 * 1.1, 1 / 3, 0.1 + 0.2, -123456789.1234567, 1e-320, 2 ** -1022].map(String);
    expect(written.slice(0, 3)).toEqual(['1.2100000000000002', '0.3333333333333333', '0.30000000000000004']);
    for (const text of [...written, '1.0', '1e2', '1E+2', '0.10']) {
      mockVerify.mockReturnValue(provenItem(`{"x":${text}}`));
      const value = JSON.parse(`{"x":${text}}`);
      await expect(verifyItemProof('00', 'k', value)).resolves.toBe(ROOT_HEX);
      await expect(verifyQueryProof('00', [value])).resolves.toBe(ROOT_HEX);
    }
  });

  it('isExactJsonNumber and firstInexactNumber', () => {
    expect(isExactJsonNumber('9007199254740991')).toBe(true);
    expect(isExactJsonNumber('-9007199254740991')).toBe(true);
    expect(isExactJsonNumber('9007199254740992')).toBe(true); // 2^53
    expect(isExactJsonNumber('9007199254740993')).toBe(false); // parses to 2^53
    expect(isExactJsonNumber('1e20')).toBe(true);
    expect(isExactJsonNumber('1000000000000000000')).toBe(true);
    expect(isExactJsonNumber('18446744073709552000')).toBe(true); // 2^64, as JavaScript writes it
    expect(isExactJsonNumber('18446744073709551616')).toBe(false); // parses to the double written 18446744073709552000
    expect(isExactJsonNumber('0.0')).toBe(true);
    expect(isExactJsonNumber('1e400')).toBe(false);
    expect(isExactJsonNumber('2.5e-308')).toBe(true);
    expect(isExactJsonNumber('2.2250738585072014e-308')).toBe(true); // 2^-1022, as JavaScript writes it
    expect(isExactJsonNumber('1e-308')).toBe(true);
    expect(isExactJsonNumber('1.2100000000000002')).toBe(true);
    expect(isExactJsonNumber('1.21000000000000020')).toBe(true); // the same value
    expect(isExactJsonNumber('1.2100000000000003')).toBe(false); // parses to the double written 1.2100000000000004
    expect(isExactJsonNumber('0.33333333333333331')).toBe(false); // parses to 0.3333333333333333
    expect(isExactJsonNumber('100')).toBe(true);
    expect(isExactJsonNumber('1.0')).toBe(true);
    expect(isExactJsonNumber('1e2')).toBe(true);
    expect(firstInexactNumber(`{"a":"1e-400","b\\"":[1,${LONG}],"c":2}`)).toBe(LONG);
    expect(firstInexactNumber('{"a":"\\"0.12345678901234567890"}')).toBeUndefined();
    expect(firstInexactNumber('{"a":1.2100000000000002,"b":[0.30000000000000004]}')).toBeUndefined();
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
