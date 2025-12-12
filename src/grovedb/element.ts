/**
 * GroveDB Element Deserialization
 *
 * Deserializes GroveDB Element types from their binary encoding.
 */

import { Element, GroveDBVerificationError } from './types';
import { BincodeReader } from './bincode';

/**
 * Element type discriminants
 */
const ELEMENT_ITEM = 0;
const ELEMENT_REFERENCE = 1;
const ELEMENT_TREE = 2;
const ELEMENT_SUM_ITEM = 3;
const ELEMENT_SUM_TREE = 4;
const ELEMENT_BIG_SUM_TREE = 5;
const ELEMENT_COUNT_TREE = 6;
const ELEMENT_COUNT_SUM_TREE = 7;

/**
 * Deserialize a GroveDB Element from bytes
 */
export function deserializeElement(bytes: Uint8Array): Element {
  const reader = new BincodeReader(bytes);
  return readElement(reader);
}

/**
 * Read an Element from a BincodeReader
 */
function readElement(reader: BincodeReader): Element {
  const elementType = reader.readU8();

  switch (elementType) {
    case ELEMENT_ITEM: {
      const value = reader.readBytes();
      const flags = readOptionBytes(reader);
      return { type: 'Item', value, flags };
    }

    case ELEMENT_REFERENCE: {
      const path = readReferencePath(reader);
      const flags = readOptionBytes(reader);
      return { type: 'Reference', path, flags };
    }

    case ELEMENT_TREE: {
      const rootKey = readOptionBytes(reader);
      const flags = readOptionBytes(reader);
      return { type: 'Tree', rootKey, flags };
    }

    case ELEMENT_SUM_ITEM: {
      const value = readI64(reader);
      const flags = readOptionBytes(reader);
      return { type: 'SumItem', value, flags };
    }

    case ELEMENT_SUM_TREE: {
      const rootKey = readOptionBytes(reader);
      const sumValue = readI64(reader);
      const flags = readOptionBytes(reader);
      return { type: 'SumTree', rootKey, sumValue, flags };
    }

    case ELEMENT_BIG_SUM_TREE: {
      const rootKey = readOptionBytes(reader);
      const sumValue = readI128(reader);
      const flags = readOptionBytes(reader);
      return { type: 'BigSumTree', rootKey, sumValue, flags };
    }

    case ELEMENT_COUNT_TREE: {
      const rootKey = readOptionBytes(reader);
      const count = readU64(reader);
      const flags = readOptionBytes(reader);
      return { type: 'CountTree', rootKey, count, flags };
    }

    case ELEMENT_COUNT_SUM_TREE: {
      const rootKey = readOptionBytes(reader);
      const count = readU64(reader);
      const sum = readI64(reader);
      const flags = readOptionBytes(reader);
      return { type: 'CountSumTree', rootKey, count, sum, flags };
    }

    default:
      throw new GroveDBVerificationError(`Unknown element type: ${elementType}`);
  }
}

/**
 * Read Option<Vec<u8>>
 */
function readOptionBytes(reader: BincodeReader): Uint8Array | null {
  const hasValue = reader.readBool();
  if (hasValue) {
    return reader.readBytes();
  }
  return null;
}

/**
 * Read reference path (Vec<Vec<u8>>)
 */
function readReferencePath(reader: BincodeReader): Uint8Array[][] {
  const length = Number(reader.readU64());
  const path: Uint8Array[][] = [];

  for (let i = 0; i < length; i++) {
    const segmentLength = Number(reader.readU64());
    const segment: Uint8Array[] = [];
    for (let j = 0; j < segmentLength; j++) {
      segment.push(reader.readBytes());
    }
    path.push(segment);
  }

  return path;
}

/**
 * Read i64 (big-endian)
 */
function readI64(reader: BincodeReader): bigint {
  const bytes = reader.readRawBytes(8);
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  // Handle sign
  if (bytes[0] & 0x80) {
    value = value - (1n << 64n);
  }
  return value;
}

/**
 * Read u64 (big-endian)
 */
function readU64(reader: BincodeReader): bigint {
  const bytes = reader.readRawBytes(8);
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

/**
 * Read i128 (big-endian)
 */
function readI128(reader: BincodeReader): bigint {
  const bytes = reader.readRawBytes(16);
  let value = 0n;
  for (let i = 0; i < 16; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  // Handle sign
  if (bytes[0] & 0x80) {
    value = value - (1n << 128n);
  }
  return value;
}

/**
 * Check if an element is a tree type (has subtrees)
 */
export function isTreeElement(element: Element): boolean {
  return (
    element.type === 'Tree' ||
    element.type === 'SumTree' ||
    element.type === 'BigSumTree' ||
    element.type === 'CountTree' ||
    element.type === 'CountSumTree'
  );
}

/**
 * Check if an element has a root key (non-empty tree)
 */
export function hasRootKey(element: Element): boolean {
  switch (element.type) {
    case 'Tree':
    case 'SumTree':
    case 'BigSumTree':
    case 'CountTree':
    case 'CountSumTree':
      return element.rootKey !== null;
    default:
      return false;
  }
}

/**
 * Get the tree feature type from an element
 */
export function getTreeFeatureType(element: Element): string | null {
  switch (element.type) {
    case 'Tree':
      return 'BasicMerkNode';
    case 'SumTree':
      return 'SummedMerkNode';
    case 'BigSumTree':
      return 'BigSummedMerkNode';
    case 'CountTree':
      return 'CountedMerkNode';
    case 'CountSumTree':
      return 'CountedSummedMerkNode';
    default:
      return null;
  }
}
