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

    const opCode = this.bytes[this.offset++];

    switch (opCode) {
      // Push variants
      case OP_PUSH_HASH:
        return { type: 'Push', node: this.decodeHash() };
      case OP_PUSH_KVHASH:
        return { type: 'Push', node: this.decodeKVHash() };
      case OP_PUSH_KV:
        return { type: 'Push', node: this.decodeKV() };
      case OP_PUSH_KVVALUEHASH:
        return { type: 'Push', node: this.decodeKVValueHash() };
      case OP_PUSH_KVDIGEST:
        return { type: 'Push', node: this.decodeKVDigest() };
      case OP_PUSH_KVREFVALUEHASH:
        return { type: 'Push', node: this.decodeKVRefValueHash() };
      case OP_PUSH_KVVALUEHASH_FEATURE_TYPE:
        return { type: 'Push', node: this.decodeKVValueHashFeatureType() };

      // PushInverted variants
      case OP_PUSH_INVERTED_HASH:
        return { type: 'PushInverted', node: this.decodeHash() };
      case OP_PUSH_INVERTED_KVHASH:
        return { type: 'PushInverted', node: this.decodeKVHash() };
      case OP_PUSH_INVERTED_KV:
        return { type: 'PushInverted', node: this.decodeKV() };
      case OP_PUSH_INVERTED_KVVALUEHASH:
        return { type: 'PushInverted', node: this.decodeKVValueHash() };
      case OP_PUSH_INVERTED_KVDIGEST:
        return { type: 'PushInverted', node: this.decodeKVDigest() };
      case OP_PUSH_INVERTED_KVREFVALUEHASH:
        return { type: 'PushInverted', node: this.decodeKVRefValueHash() };
      case OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE:
        return { type: 'PushInverted', node: this.decodeKVValueHashFeatureType() };

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
  private decodeKV(): MerkNode {
    const keyLen = this.bytes[this.offset++];
    const key = this.readBytes(keyLen);
    const valueLen = this.readU16();
    const value = this.readBytes(valueLen);
    return { type: 'KV', key, value };
  }

  /**
   * Decode a KVValueHash node
   */
  private decodeKVValueHash(): MerkNode {
    const keyLen = this.bytes[this.offset++];
    const key = this.readBytes(keyLen);
    const valueLen = this.readU16();
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVValueHash', key, value, valueHash };
  }

  /**
   * Decode a KVDigest node
   */
  private decodeKVDigest(): MerkNode {
    const keyLen = this.bytes[this.offset++];
    const key = this.readBytes(keyLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVDigest', key, valueHash };
  }

  /**
   * Decode a KVRefValueHash node
   */
  private decodeKVRefValueHash(): MerkNode {
    const keyLen = this.bytes[this.offset++];
    const key = this.readBytes(keyLen);
    const valueLen = this.readU16();
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    return { type: 'KVRefValueHash', key, value, valueHash };
  }

  /**
   * Decode a KVValueHashFeatureType node
   */
  private decodeKVValueHashFeatureType(): MerkNode {
    const keyLen = this.bytes[this.offset++];
    const key = this.readBytes(keyLen);
    const valueLen = this.readU16();
    const value = this.readBytes(valueLen);
    const valueHash = this.readBytes(HASH_LENGTH);
    const featureType = this.decodeFeatureType();
    return { type: 'KVValueHashFeatureType', key, value, valueHash, featureType };
  }

  /**
   * Decode TreeFeatureType
   */
  private decodeFeatureType(): TreeFeatureType {
    const featureCode = this.bytes[this.offset++];

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
