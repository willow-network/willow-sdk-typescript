/**
 * GroveDB Proof Types
 *
 * Type definitions matching the Rust GroveDB proof structures.
 */

/** 32-byte cryptographic hash */
export type CryptoHash = Uint8Array;

/** Hash length constant */
export const HASH_LENGTH = 32;

/** Null hash (all zeros) */
export const NULL_HASH: CryptoHash = new Uint8Array(32);

/**
 * Tree feature types for sum trees, count trees, etc.
 */
export type TreeFeatureType =
  | { type: 'BasicMerkNode' }
  | { type: 'SummedMerkNode'; sum: bigint }
  | { type: 'BigSummedMerkNode'; sum: bigint }
  | { type: 'CountedMerkNode'; count: bigint }
  | { type: 'CountedSummedMerkNode'; count: bigint; sum: bigint };

/**
 * Merk proof node types
 */
export type MerkNode =
  | { type: 'Hash'; hash: CryptoHash }
  | { type: 'KVHash'; kvHash: CryptoHash }
  | { type: 'KV'; key: Uint8Array; value: Uint8Array }
  | { type: 'KVValueHash'; key: Uint8Array; value: Uint8Array; valueHash: CryptoHash }
  | { type: 'KVDigest'; key: Uint8Array; valueHash: CryptoHash }
  | { type: 'KVRefValueHash'; key: Uint8Array; value: Uint8Array; valueHash: CryptoHash }
  | { type: 'KVValueHashFeatureType'; key: Uint8Array; value: Uint8Array; valueHash: CryptoHash; featureType: TreeFeatureType };

/**
 * Merk proof operations
 */
export type MerkOp =
  | { type: 'Push'; node: MerkNode }
  | { type: 'PushInverted'; node: MerkNode }
  | { type: 'Parent' }
  | { type: 'Child' }
  | { type: 'ParentInverted' }
  | { type: 'ChildInverted' };

/**
 * Prove options
 *
 * Decoded for wire-format completeness. The SDK does not replicate the
 * `decreaseLimitOnEmptySubQueryResult` limit-accounting detail of the Rust
 * verifier — proofs verify identically, but the *remaining limit* reported for
 * proofs generated with that option may differ.
 */
export interface ProveOptions {
  decreaseLimitOnEmptySubQueryResult: boolean;
}

/**
 * Layer proof - contains Merk proof and nested subtree proofs
 */
export interface LayerProof {
  merkProof: Uint8Array;
  lowerLayers: Map<string, LayerProof>; // Key is hex-encoded for Map compatibility
}

/**
 * GroveDB Proof V0
 */
export interface GroveDBProofV0 {
  rootLayer: LayerProof;
  proveOptions: ProveOptions;
}

/**
 * GroveDB Proof (versioned enum)
 */
export type GroveDBProof =
  | { version: 0; proof: GroveDBProofV0 };

/**
 * Proved key-value pair from verification
 */
export interface ProvedKeyValue {
  key: Uint8Array;
  value: Uint8Array | null;
  proof: CryptoHash;
}

/**
 * GroveDB Element types (subset needed for verification)
 */
export type Element =
  | { type: 'Item'; value: Uint8Array; flags: Uint8Array | null }
  | { type: 'Reference'; path: Uint8Array[]; flags: Uint8Array | null }
  | { type: 'Tree'; rootKey: Uint8Array | null; flags: Uint8Array | null }
  | { type: 'SumTree'; rootKey: Uint8Array | null; sumValue: bigint; flags: Uint8Array | null }
  | { type: 'SumItem'; value: bigint; flags: Uint8Array | null }
  | { type: 'BigSumTree'; rootKey: Uint8Array | null; sumValue: bigint; flags: Uint8Array | null }
  | { type: 'CountTree'; rootKey: Uint8Array | null; count: bigint; flags: Uint8Array | null }
  | { type: 'CountSumTree'; rootKey: Uint8Array | null; count: bigint; sum: bigint; flags: Uint8Array | null };

/**
 * Verification error
 */
export class GroveDBVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GroveDBVerificationError';
  }
}
