/**
 * Bincode Decoder for GroveDB Proofs
 *
 * Decodes the outer bincode-encoded GroveDBProof structure.
 * Uses big-endian encoding as specified in GroveDB.
 */

import { GroveDBProof, GroveDBProofV0, LayerProof, ProveOptions, GroveDBVerificationError } from './types';

/**
 * Bincode reader for big-endian encoded data
 */
export class BincodeReader {
  private data: Uint8Array;
  private offset: number = 0;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  /**
   * Get current position
   */
  position(): number {
    return this.offset;
  }

  /**
   * Check if there's more data
   */
  hasMore(): boolean {
    return this.offset < this.data.length;
  }

  /**
   * Read a single byte
   */
  readU8(): number {
    if (this.offset >= this.data.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u8');
    }
    return this.data[this.offset++];
  }

  /**
   * Read a big-endian u16
   */
  readU16(): number {
    if (this.offset + 2 > this.data.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u16');
    }
    const value = (this.data[this.offset] << 8) | this.data[this.offset + 1];
    this.offset += 2;
    return value;
  }

  /**
   * Read a big-endian u32
   */
  readU32(): number {
    if (this.offset + 4 > this.data.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u32');
    }
    const value =
      (this.data[this.offset] << 24) |
      (this.data[this.offset + 1] << 16) |
      (this.data[this.offset + 2] << 8) |
      this.data[this.offset + 3];
    this.offset += 4;
    return value >>> 0; // Convert to unsigned
  }

  /**
   * Read a big-endian u64 as bigint
   */
  readU64(): bigint {
    if (this.offset + 8 > this.data.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u64');
    }
    let value = 0n;
    for (let i = 0; i < 8; i++) {
      value = (value << 8n) | BigInt(this.data[this.offset + i]);
    }
    this.offset += 8;
    return value;
  }

  /**
   * Read a boolean
   */
  readBool(): boolean {
    const value = this.readU8();
    if (value !== 0 && value !== 1) {
      throw new GroveDBVerificationError(`Invalid boolean value: ${value}`);
    }
    return value === 1;
  }

  /**
   * Read a length-prefixed byte array (bincode uses u64 for lengths)
   */
  readBytes(): Uint8Array {
    const length = Number(this.readU64());
    if (length > 1_000_000_000) {
      throw new GroveDBVerificationError(`Suspiciously large byte array length: ${length}`);
    }
    if (this.offset + length > this.data.length) {
      throw new GroveDBVerificationError(`Unexpected end of data reading ${length} bytes`);
    }
    const bytes = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  /**
   * Read raw bytes without length prefix
   */
  readRawBytes(length: number): Uint8Array {
    if (this.offset + length > this.data.length) {
      throw new GroveDBVerificationError(`Unexpected end of data reading ${length} raw bytes`);
    }
    const bytes = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }
}

/**
 * Decode a LayerProof from bincode
 */
function decodeLayerProof(reader: BincodeReader): LayerProof {
  // merk_proof: Vec<u8>
  const merkProof = reader.readBytes();

  // lower_layers: BTreeMap<Key, LayerProof>
  const mapLength = Number(reader.readU64());
  const lowerLayers = new Map<string, LayerProof>();

  for (let i = 0; i < mapLength; i++) {
    // Key is Vec<u8>
    const key = reader.readBytes();
    const keyHex = bytesToHex(key);

    // Value is LayerProof (recursive)
    const layerProof = decodeLayerProof(reader);

    lowerLayers.set(keyHex, layerProof);
  }

  return { merkProof, lowerLayers };
}

/**
 * Decode ProveOptions from bincode
 */
function decodeProveOptions(reader: BincodeReader): ProveOptions {
  return {
    decreaseLimitOnEmptySubQueryResult: reader.readBool()
  };
}

/**
 * Decode GroveDBProofV0 from bincode
 */
function decodeGroveDBProofV0(reader: BincodeReader): GroveDBProofV0 {
  const rootLayer = decodeLayerProof(reader);
  const proveOptions = decodeProveOptions(reader);

  return { rootLayer, proveOptions };
}

/**
 * Decode a GroveDBProof from bincode-encoded bytes
 */
export function decodeGroveDBProof(bytes: Uint8Array): GroveDBProof {
  const reader = new BincodeReader(bytes);

  // Read enum variant (u32 for bincode enums)
  const variant = reader.readU32();

  if (variant !== 0) {
    throw new GroveDBVerificationError(`Unknown GroveDBProof version: ${variant}`);
  }

  const proof = decodeGroveDBProofV0(reader);

  // Trailing bytes are acceptable - proof may include extra data for future compatibility

  return { version: 0, proof };
}

/**
 * Helper: Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Helper: Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}
