/**
 * Varint Encoding/Decoding
 *
 * LEB128-style variable-length integer encoding used by GroveDB.
 */

/**
 * Varint decoding error
 */
export class VarintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VarintError';
  }
}

const U64_MAX = (1n << 64n) - 1n;

/**
 * Encode a number as a varint.
 *
 * Accepts any non-negative integer up to `Number.MAX_SAFE_INTEGER`. Uses
 * arithmetic (not 32-bit bitwise ops) so values ≥ 2^31 encode correctly.
 */
export function encodeVarint(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new VarintError(`Cannot encode ${value} as varint (need a non-negative safe integer)`);
  }
  const bytes: number[] = [];
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80);
    value = Math.floor(value / 128);
  }
  bytes.push(value);
  return new Uint8Array(bytes);
}

/**
 * Decode a varint from bytes, returning the value and bytes consumed.
 *
 * Uses arithmetic (not 32-bit bitwise ops) so values ≥ 2^31 decode correctly,
 * and throws once a value can no longer be represented exactly in a JS number
 * — use {@link decodeVarint64} for the full u64 range.
 */
export function decodeVarint(bytes: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value += (byte & 0x7f) * 2 ** shift;
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new VarintError('Varint exceeds Number.MAX_SAFE_INTEGER — use decodeVarint64');
    }

    if ((byte & 0x80) === 0) {
      return { value, bytesRead };
    }

    shift += 7;
  }

  throw new VarintError('Unexpected end of varint');
}

/**
 * Decode a signed varint (zigzag encoded)
 */
export function decodeSignedVarint(bytes: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
  const { value: unsigned, bytesRead } = decodeVarint(bytes, offset);
  // Zigzag decode: (n >>> 1) ^ -(n & 1). Arithmetic form to stay exact > 2^31.
  const half = Math.floor(unsigned / 2);
  const signed = unsigned % 2 === 0 ? half : -half - 1;
  return { value: signed, bytesRead };
}

/**
 * Decode an unsigned 64-bit varint as bigint.
 *
 * A u64 needs at most 10 LEB128 bytes; anything longer — or a decoded value
 * past 2^64-1 — is rejected rather than silently wrapped.
 */
export function decodeVarint64(bytes: Uint8Array, offset: number = 0): { value: bigint; bytesRead: number } {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value |= BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      if (value > U64_MAX) {
        throw new VarintError('Varint exceeds u64 range');
      }
      return { value, bytesRead };
    }

    shift += 7n;

    if (shift > 63n) {
      throw new VarintError('Varint too long for u64');
    }
  }

  throw new VarintError('Unexpected end of varint');
}

/**
 * Decode a 64-bit signed varint (zigzag encoded) as bigint.
 */
export function decodeSignedVarint64(bytes: Uint8Array, offset: number = 0): { value: bigint; bytesRead: number } {
  const { value: unsigned, bytesRead } = decodeVarint64(bytes, offset);
  // Zigzag decode for signed
  const signed = (unsigned >> 1n) ^ -(unsigned & 1n);
  return { value: signed, bytesRead };
}
