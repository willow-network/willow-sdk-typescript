/**
 * Merk Operation Decoder
 *
 * Decodes the binary format of Merk proof operations.
 */

import { MerkOp, MerkNode, TreeFeatureType, HASH_LENGTH, GroveDBVerificationError } from './types';
import { decodeSignedVarint64, decodeVarint64 } from './varint';

/**
 * Op codes for Merk operations
 */
const OP_PUSH_HASH = 0x01;
const OP_PUSH_KVHASH = 0x02;
const OP_PUSH_KV = 0x03;
const OP_PUSH_KVVALUEHASH = 0x04;
const OP_PUSH_KVDIGEST = 0x05;
const OP_PUSH_KVREFVALUEHASH = 0x06;
const OP_PUSH_KVVALUEHASH_FEATURE_TYPE = 0x07;
const OP_PUSH_INVERTED_HASH = 0x08;
const OP_PUSH_INVERTED_KVHASH = 0x09;
const OP_PUSH_INVERTED_KV = 0x0a;
const OP_PUSH_INVERTED_KVVALUEHASH = 0x0b;
const OP_PUSH_INVERTED_KVDIGEST = 0x0c;
const OP_PUSH_INVERTED_KVREFVALUEHASH = 0x0d;
const OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE = 0x0e;
const OP_PARENT = 0x10;
const OP_CHILD = 0x11;
const OP_PARENT_INVERTED = 0x12;
const OP_CHILD_INVERTED = 0x13;

/**
 * Large-value op codes: the same layout as the op they mirror, but the value
 * length is a big-endian u32. The Willow GroveDB fork (willow-network/grovedb,
 * branch willow/v3.1.0-proof-fixes; upstream dashpay/grovedb 86562f65) writes
 * them for any value of 64 KiB or more, which grovedb 3.1.0's u16 length
 * cannot express.
 */
const OP_PUSH_KV_LARGE = 0x20;
const OP_PUSH_KVVALUEHASH_LARGE = 0x21;
const OP_PUSH_KVREFVALUEHASH_LARGE = 0x22;
const OP_PUSH_KVVALUEHASH_FEATURE_TYPE_LARGE = 0x23;
const OP_PUSH_INVERTED_KV_LARGE = 0x28;
const OP_PUSH_INVERTED_KVVALUEHASH_LARGE = 0x29;
const OP_PUSH_INVERTED_KVREFVALUEHASH_LARGE = 0x2a;
const OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE_LARGE = 0x2b;

/** A value this long or longer must use a large-value op (and only those may). */
export const LARGE_VALUE_THRESHOLD = 65536;
/** Longest value a large-value op may declare (64 MiB, as the prover's decoder). */
export const MAX_VALUE_LEN = 64 * 1024 * 1024;

/**
 * Feature type encoding
 */
const FEATURE_BASIC = 0x00;
const FEATURE_SUMMED = 0x01;
const FEATURE_BIG_SUMMED = 0x02;
const FEATURE_COUNTED = 0x03;
const FEATURE_COUNTED_SUMMED = 0x04;

/**
 * Decoder class for iterating through Merk operations
 */
export class MerkDecoder implements Iterable<MerkOp> {
  private bytes: Uint8Array;
  private offset: number = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /**
   * Check if there are more operations to decode
   */
  hasMore(): boolean {
    return this.offset < this.bytes.length;
  }

  /**
   * Decode the next operation
   */
  next(): MerkOp | null {
    if (!this.hasMore()) {
      return null;
    }

    const opCode = this.readU8('op code');

    switch (opCode) {
      // Push variants
      case OP_PUSH_HASH:
        return { type: 'Push', node: this.decodeHash() };
      case OP_PUSH_KVHASH:
        return { type: 'Push', node: this.decodeKVHash() };
      case OP_PUSH_KV:
        return { type: 'Push', node: this.decodeKV(false) };
      case OP_PUSH_KVVALUEHASH:
        return { type: 'Push', node: this.decodeKVValueHash(false) };
      case OP_PUSH_KVDIGEST:
        return { type: 'Push', node: this.decodeKVDigest() };
      case OP_PUSH_KVREFVALUEHASH:
        return { type: 'Push', node: this.decodeKVRefValueHash(false) };
      case OP_PUSH_KVVALUEHASH_FEATURE_TYPE:
        return { type: 'Push', node: this.decodeKVValueHashFeatureType(false) };
      case OP_PUSH_KV_LARGE:
        return { type: 'Push', node: this.decodeKV(true) };
      case OP_PUSH_KVVALUEHASH_LARGE:
        return { type: 'Push', node: this.decodeKVValueHash(true) };
      case OP_PUSH_KVREFVALUEHASH_LARGE:
        return { type: 'Push', node: this.decodeKVRefValueHash(true) };
      case OP_PUSH_KVVALUEHASH_FEATURE_TYPE_LARGE:
        return { type: 'Push', node: this.decodeKVValueHashFeatureType(true) };

      // PushInverted variants
      case OP_PUSH_INVERTED_HASH:
        return { type: 'PushInverted', node: this.decodeHash() };
      case OP_PUSH_INVERTED_KVHASH:
        return { type: 'PushInverted', node: this.decodeKVHash() };
      case OP_PUSH_INVERTED_KV:
        return { type: 'PushInverted', node: this.decodeKV(false) };
      case OP_PUSH_INVERTED_KVVALUEHASH:
        return { type: 'PushInverted', node: this.decodeKVValueHash(false) };
      case OP_PUSH_INVERTED_KVDIGEST:
        return { type: 'PushInverted', node: this.decodeKVDigest() };
      case OP_PUSH_INVERTED_KVREFVALUEHASH:
        return { type: 'PushInverted', node: this.decodeKVRefValueHash(false) };
      case OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE:
        return { type: 'PushInverted', node: this.decodeKVValueHashFeatureType(false) };
      case OP_PUSH_INVERTED_KV_LARGE:
        return { type: 'PushInverted', node: this.decodeKV(true) };
      case OP_PUSH_INVERTED_KVVALUEHASH_LARGE:
        return { type: 'PushInverted', node: this.decodeKVValueHash(true) };
      case OP_PUSH_INVERTED_KVREFVALUEHASH_LARGE:
        return { type: 'PushInverted', node: this.decodeKVRefValueHash(true) };
      case OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE_LARGE:
        return { type: 'PushInverted', node: this.decodeKVValueHashFeatureType(true) };

      // Tree operations
      case OP_PARENT:
        return { type: 'Parent' };
      case OP_CHILD:
        return { type: 'Child' };
      case OP_PARENT_INVERTED:
        return { type: 'ParentInverted' };
      case OP_CHILD_INVERTED:
        return { type: 'ChildInverted' };

      default:
        throw new GroveDBVerificationError(`Unknown op code: 0x${opCode.toString(16)}`);
    }
  }

  /**
   * Decode a Hash node
   */
  private decodeHash(): MerkNode {
    const hash = this.readBytes(HASH_LENGTH);
    return { type: 'Hash', hash };
  }

  /**
   * Decode a KVHash node
   */
  private decodeKVHash(): MerkNode {
    const kvHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVHash', kvHash };
  }

  /**
   * Decode a KV node
   */
  private decodeKV(large: boolean): MerkNode {
    const keyLen = this.readU8('key length');
    const key = this.readBytes(keyLen);
    const valueLen = this.readValueLength(large);
    const value = this.readBytes(valueLen);
    return { type: 'KV', key, value };
  }

  /**
   * Decode a KVValueHash node
   */
  private decodeKVValueHash(large: boolean): MerkNode {
    const keyLen = this.readU8('key length');
    const key = this.readBytes(keyLen);
    const valueLen = this.readValueLength(large);
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVValueHash', key, value, valueHash };
  }

  /**
   * Decode a KVDigest node
   */
  private decodeKVDigest(): MerkNode {
    const keyLen = this.readU8('key length');
    const key = this.readBytes(keyLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVDigest', key, valueHash };
  }

  /**
   * Decode a KVRefValueHash node
   */
  private decodeKVRefValueHash(large: boolean): MerkNode {
    const keyLen = this.readU8('key length');
    const key = this.readBytes(keyLen);
    const valueLen = this.readValueLength(large);
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVRefValueHash', key, value, valueHash };
  }

  /**
   * Decode a KVValueHashFeatureType node
   */
  private decodeKVValueHashFeatureType(large: boolean): MerkNode {
    const keyLen = this.readU8('key length');
    const key = this.readBytes(keyLen);
    const valueLen = this.readValueLength(large);
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    const featureType = this.decodeFeatureType();
    return { type: 'KVValueHashFeatureType', key, value, valueHash, featureType };
  }

  /**
   * Decode TreeFeatureType
   */
  private decodeFeatureType(): TreeFeatureType {
    const featureCode = this.readU8('feature type');

    switch (featureCode) {
      case FEATURE_BASIC:
        return { type: 'BasicMerkNode' };

      case FEATURE_SUMMED: {
        const { value, bytesRead } = decodeSignedVarint64(this.bytes, this.offset);
        this.offset += bytesRead;
        return { type: 'SummedMerkNode', sum: value };
      }

      case FEATURE_BIG_SUMMED: {
        // Big sum is encoded as 16 bytes (i128)
        const sumBytes = this.readBytes(16);
        // Little-endian i128 to bigint
        let sum = 0n;
        for (let i = 0; i < 16; i++) {
          sum |= BigInt(sumBytes[i]) << BigInt(i * 8);
        }
        // Handle sign for i128
        if (sumBytes[15] & 0x80) {
          sum = sum - (1n << 128n);
        }
        return { type: 'BigSummedMerkNode', sum };
      }

      case FEATURE_COUNTED: {
        const { value, bytesRead } = decodeVarint64(this.bytes, this.offset);
        this.offset += bytesRead;
        return { type: 'CountedMerkNode', count: value };
      }

      case FEATURE_COUNTED_SUMMED: {
        const { value: count, bytesRead: countBytes } = decodeVarint64(this.bytes, this.offset);
        this.offset += countBytes;
        const { value: sum, bytesRead: sumBytes } = decodeSignedVarint64(this.bytes, this.offset);
        this.offset += sumBytes;
        return { type: 'CountedSummedMerkNode', count, sum };
      }

      default:
        throw new GroveDBVerificationError(`Unknown feature type: 0x${featureCode.toString(16)}`);
    }
  }

  /**
   * Read a single byte
   */
  private readU8(context: string): number {
    if (this.offset >= this.bytes.length) {
      throw new GroveDBVerificationError(`Unexpected end of data reading ${context}`);
    }
    return this.bytes[this.offset++];
  }

  /**
   * Read a big-endian u16
   */
  private readU16(): number {
    if (this.offset + 2 > this.bytes.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u16');
    }
    const value = (this.bytes[this.offset] << 8) | this.bytes[this.offset + 1];
    this.offset += 2;
    return value;
  }

  /**
   * Read a value length: a big-endian u16 for the 3.1.0 ops, a big-endian u32
   * for the large-value ops. A large-value op must carry a value of at least
   * 64 KiB (a shorter one has exactly one encoding, the u16 op) and at most
   * MAX_VALUE_LEN.
   */
  private readValueLength(large: boolean): number {
    if (!large) {
      return this.readU16();
    }
    const len = this.readU32();
    if (len < LARGE_VALUE_THRESHOLD) {
      throw new GroveDBVerificationError(
        `Large-value op with a ${len}-byte value (must be at least ${LARGE_VALUE_THRESHOLD})`,
      );
    }
    if (len > MAX_VALUE_LEN) {
      throw new GroveDBVerificationError(
        `Large-value op with a ${len}-byte value (limit ${MAX_VALUE_LEN})`,
      );
    }
    return len;
  }

  /**
   * Read a big-endian u32 (without 32-bit signed bitwise arithmetic)
   */
  private readU32(): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new GroveDBVerificationError('Unexpected end of data reading u32');
    }
    const b = this.bytes;
    const o = this.offset;
    const value = b[o] * 0x1000000 + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
    this.offset += 4;
    return value;
  }

  /**
   * Read a fixed number of bytes
   */
  private readBytes(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) {
      throw new GroveDBVerificationError(`Unexpected end of data reading ${length} bytes`);
    }
    const bytes = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  /**
   * Iterator implementation
   */
  *[Symbol.iterator](): Iterator<MerkOp> {
    let op: MerkOp | null;
    while ((op = this.next()) !== null) {
      yield op;
    }
  }
}

/**
 * Decode all Merk operations from bytes
 */
export function decodeMerkOps(bytes: Uint8Array): MerkOp[] {
  const decoder = new MerkDecoder(bytes);
  return [...decoder];
}
