/**
 * GroveDB Proof Verification Module
 *
 * Pure TypeScript implementation of GroveDB proof verification.
 * This allows trustless verification of data returned by Willow nodes.
 */

// Main verifier
export {
  verifyGroveDBProof,
  verifyProofAgainstRoot,
  quickVerify,
  GroveDBVerificationResult,
  VerifyOptions
} from './verifier';

// Types
export {
  GroveDBProof,
  GroveDBProofV0,
  LayerProof,
  ProveOptions,
  MerkOp,
  MerkNode,
  TreeFeatureType,
  Element,
  CryptoHash,
  ProvedKeyValue,
  GroveDBVerificationError,
  HASH_LENGTH,
  NULL_HASH
} from './types';

// Bincode 2 reader + hex helpers
export {
  BincodeReader,
  bytesToHex,
  hexToBytes
} from './bincode';

// GroveDBProof decoder (bincode 2)
export { decodeGroveDBProof } from './decoder';

// Hash functions
export {
  blake3Hash,
  valueHash,
  kvHash,
  kvDigestToKvHash,
  nodeHash,
  combineHash,
  hashEquals,
  hashToHex,
  hexToHash
} from './hash';

// Merk operations
export { MerkDecoder, decodeMerkOps } from './merk-decoder';

// Executor
export {
  executeOps,
  executeMerkProof,
  executeMerkProofWithQuery,
  MerkExecutionResult
} from './executor';

// Tree structure
export { Tree, Child, compareBytes } from './tree';

// Element handling
export {
  deserializeElement,
  isTreeElement,
  hasRootKey,
  getTreeFeatureType
} from './element';

// Varint utilities
export {
  encodeVarint,
  decodeVarint,
  decodeSignedVarint,
  decodeSignedVarint64,
  decodeVarint64,
  VarintError
} from './varint';
