/**
 * GroveDB Hash Functions
 *
 * All hash functions use BLAKE3, matching the Rust implementation.
 *
 * We use `@noble/hashes/blake3` (pure TS, sync, isomorphic) rather than the
 * `blake3` npm package, which has a Node/browser split where the default
 * entry point requires async WebAssembly loading in browsers. `@noble/hashes`
 * is already a transitive dependency via other modules and works the same
 * way in Node, the browser, and any bundler target.
 */

import { blake3 } from '@noble/hashes/blake3';
import { encodeVarint } from './varint';
import { bytesToHex, hexToBytes } from './bincode';
import { CryptoHash, HASH_LENGTH, NULL_HASH, GroveDBVerificationError } from './types';

/**
 * Compute BLAKE3 hash of data
 */
export function blake3Hash(data: Uint8Array): CryptoHash {
  return blake3(data);
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
  return bytesToHex(h);
}

/**
 * Convert hex string to hash
 */
export function hexToHash(hex: string): CryptoHash {
  const bytes = hexToBytes(hex);
  if (bytes.length !== HASH_LENGTH) {
    throw new GroveDBVerificationError(
      `Invalid hash hex length: ${bytes.length} bytes, expected ${HASH_LENGTH}`
    );
  }
  return bytes;
}
