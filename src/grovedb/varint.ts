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

/**
 * Encode a number as a varint
 */
export function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value);
  return new Uint8Array(bytes);
}

/**
 * Decode a varint from bytes, returning the value and bytes consumed
 */
export function decodeVarint(bytes: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value |= (byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      return { value, bytesRead };
    }

    shift += 7;

    if (shift > 35) {
      throw new VarintError('Varint too long');
    }
  }

  throw new VarintError('Unexpected end of varint');
}

/**
 * Decode a signed varint (zigzag encoded)
 */
export function decodeSignedVarint(bytes: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
  const { value: unsigned, bytesRead } = decodeVarint(bytes, offset);
  // Zigzag decode: (n >>> 1) ^ -(n & 1)
  const signed = (unsigned >>> 1) ^ -(unsigned & 1);
  return { value: signed, bytesRead };
}

/**
 * Decode a 64-bit signed varint as bigint
 */
export function decodeSignedVarint64(bytes: Uint8Array, offset: number = 0): { value: bigint; bytesRead: number } {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value |= BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      // Zigzag decode for signed
      const signed = (value >> 1n) ^ -(value & 1n);
      return { value: signed, bytesRead };
    }

    shift += 7n;

    if (shift > 70n) {
      throw new VarintError('Varint too long');
    }
  }

  throw new VarintError('Unexpected end of varint');
}

/**
 * Decode an unsigned 64-bit varint as bigint
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
      return { value, bytesRead };
    }

    shift += 7n;

    if (shift > 70n) {
      throw new VarintError('Varint too long');
    }
  }

  throw new VarintError('Unexpected end of varint');
}
