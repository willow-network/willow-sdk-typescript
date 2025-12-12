/**
 * GroveDB Hash Functions
 *
 * All hash functions use BLAKE3, matching the Rust implementation.
 */

import { hash } from 'blake3';
import { encodeVarint } from './varint';
import { CryptoHash, HASH_LENGTH, NULL_HASH, GroveDBVerificationError } from './types';

/**
 * Compute BLAKE3 hash of data
 */
export function blake3Hash(data: Uint8Array): CryptoHash {
  // blake3.hash returns Buffer which extends Uint8Array
  const result = hash(data);
  // Handle both Buffer and string return types
  if (typeof result === 'string') {
    // Should not happen with default options, but handle it
    throw new GroveDBVerificationError('blake3 returned string instead of Buffer');
  }
  // Convert Buffer to Uint8Array
  return Uint8Array.from(result);
}

/**
 * Hash a value with its length prefix
 * value_hash(value) = BLAKE3(varint(value.length) || value)
 */
export function valueHash(value: Uint8Array): CryptoHash {
  const lengthPrefix = encodeVarint(value.length);
  const combined = new Uint8Array(lengthPrefix.length + value.length);
  combined.set(lengthPrefix, 0);
  combined.set(value, lengthPrefix.length);
  return blake3Hash(combined);
}

/**
 * Hash a key-value pair
 * kv_hash(key, value) = BLAKE3(varint(key.length) || key || value_hash(value))
 */
export function kvHash(key: Uint8Array, value: Uint8Array): CryptoHash {
  const keyLengthPrefix = encodeVarint(key.length);
  const valHash = valueHash(value);

  const combined = new Uint8Array(keyLengthPrefix.length + key.length + HASH_LENGTH);
  let offset = 0;
  combined.set(keyLengthPrefix, offset);
  offset += keyLengthPrefix.length;
  combined.set(key, offset);
  offset += key.length;
  combined.set(valHash, offset);

  return blake3Hash(combined);
}

/**
 * Compute kv_hash from key and pre-computed value hash
 * kv_digest_to_kv_hash(key, value_hash) = BLAKE3(varint(key.length) || key || value_hash)
 */
export function kvDigestToKvHash(key: Uint8Array, valHash: CryptoHash): CryptoHash {
  const keyLengthPrefix = encodeVarint(key.length);

  const combined = new Uint8Array(keyLengthPrefix.length + key.length + HASH_LENGTH);
  let offset = 0;
  combined.set(keyLengthPrefix, offset);
  offset += keyLengthPrefix.length;
  combined.set(key, offset);
  offset += key.length;
  combined.set(valHash, offset);

  return blake3Hash(combined);
}

/**
 * Hash a node with its children
 * node_hash(kv, left, right) = BLAKE3(kv || left || right)
 */
export function nodeHash(kv: CryptoHash, left: CryptoHash, right: CryptoHash): CryptoHash {
  const combined = new Uint8Array(HASH_LENGTH * 3);
  combined.set(kv, 0);
  combined.set(left, HASH_LENGTH);
  combined.set(right, HASH_LENGTH * 2);
  return blake3Hash(combined);
}

/**
 * Combine two hashes
 * combine_hash(a, b) = BLAKE3(a || b)
 */
export function combineHash(a: CryptoHash, b: CryptoHash): CryptoHash {
  const combined = new Uint8Array(HASH_LENGTH * 2);
  combined.set(a, 0);
  combined.set(b, HASH_LENGTH);
  return blake3Hash(combined);
}

/**
 * Check if two hashes are equal
 */
export function hashEquals(a: CryptoHash, b: CryptoHash): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Check if a hash is the null hash (all zeros)
 */
export function isNullHash(h: CryptoHash): boolean {
  return hashEquals(h, NULL_HASH);
}

/**
 * Convert hash to hex string
 */
export function hashToHex(h: CryptoHash): string {
  return Array.from(h, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to hash
 */
export function hexToHash(hex: string): CryptoHash {
  const clean = hex.replace(/^0x/, '');
  if (clean.length !== HASH_LENGTH * 2) {
    throw new GroveDBVerificationError(`Invalid hash hex length: ${clean.length}, expected ${HASH_LENGTH * 2}`);
  }
  const bytes = new Uint8Array(HASH_LENGTH);
  for (let i = 0; i < HASH_LENGTH; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}
