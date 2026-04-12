/**
 * GroveDB Proof Verifier
 *
 * Main entry point for verifying GroveDB proofs.
 * Handles nested layer verification and returns proven results.
 */

import {
  GroveDBProof,
  LayerProof,
  CryptoHash,
  GroveDBVerificationError,
  ProvedKeyValue,
  Element
} from './types';
import { bytesToHex, hexToBytes } from './bincode';
import { decodeGroveDBProof } from './decoder';
import { executeMerkProofWithQuery, MerkExecutionResult } from './executor';
import { deserializeElement, isTreeElement, hasRootKey } from './element';
import { combineHash, valueHash, hashEquals, hashToHex } from './hash';

/**
 * Result of verifying a GroveDB proof
 */
export interface GroveDBVerificationResult {
  /** Root hash of the entire GroveDB tree */
  rootHash: CryptoHash;
  /** Proven key-value pairs with their paths */
  results: Array<{
    path: Uint8Array[];
    key: Uint8Array;
    value: Uint8Array | null;
    element: Element | null;
  }>;
}

/**
 * Options for proof verification
 */
export interface VerifyOptions {
  /** Maximum number of results to return */
  limit?: number;
  /** Whether to deserialize element values */
  deserializeElements?: boolean;
}

/**
 * Verify a GroveDB proof and return the root hash and proven values
 *
 * @param proofBytes - The bincode-encoded GroveDBProof
 * @param options - Verification options
 * @returns Verification result with root hash and proven values
 */
export function verifyGroveDBProof(
  proofBytes: Uint8Array,
  options: VerifyOptions = {}
): GroveDBVerificationResult {
  const proof = decodeGroveDBProof(proofBytes);
  return verifyProof(proof, options);
}

/**
 * Verify a decoded GroveDB proof
 */
function verifyProof(
  proof: GroveDBProof,
  options: VerifyOptions
): GroveDBVerificationResult {
  if (proof.version !== 0) {
    throw new GroveDBVerificationError(`Unsupported proof version: ${proof.version}`);
  }

  const results: GroveDBVerificationResult['results'] = [];
  let limit = options.limit ?? null;
  const deserializeElements = options.deserializeElements ?? true;

  const rootHash = verifyLayerProof(
    proof.proof.rootLayer,
    proof.proof.proveOptions.decreaseLimitOnEmptySubQueryResult,
    [],
    results,
    limit,
    deserializeElements
  );

  return { rootHash, results };
}

/**
 * Verify a layer proof recursively
 *
 * @param layerProof - The layer proof to verify
 * @param decreaseLimitOnEmpty - Whether to decrease limit on empty results
 * @param currentPath - Current path in the tree
 * @param results - Accumulator for proven values
 * @param limit - Maximum results (null for unlimited)
 * @param deserializeElements - Whether to parse element bytes
 * @returns Root hash of this layer
 */
function verifyLayerProof(
  layerProof: LayerProof,
  decreaseLimitOnEmpty: boolean,
  currentPath: Uint8Array[],
  results: GroveDBVerificationResult['results'],
  limit: number | null,
  deserializeElements: boolean
): CryptoHash {
  // Execute the Merk proof to get root hash and values
  const merkResult = executeMerkProofWithQuery(
    layerProof.merkProof,
    limit,
    true // left to right
  );

  // Process each proven value
  for (const proved of merkResult.resultSet) {
    // Check if this key has a lower layer proof (subtree)
    const keyHex = bytesToHex(proved.key);
    const lowerLayer = layerProof.lowerLayers.get(keyHex);

    if (lowerLayer && proved.value) {
      // This is a subtree - verify the lower layer
      let element: Element | null = null;
      if (deserializeElements) {
        try {
          element = deserializeElement(proved.value);
        } catch (e) {
          // If deserialization fails, treat as opaque bytes
          element = null;
        }
      }

      // Only recurse if element is a tree type with a root key
      if (element && isTreeElement(element) && hasRootKey(element)) {
        const newPath = [...currentPath, proved.key];

        // Recursively verify the lower layer
        const lowerHash = verifyLayerProof(
          lowerLayer,
          decreaseLimitOnEmpty,
          newPath,
          results,
          limit !== null ? limit - results.length : null,
          deserializeElements
        );

        // Verify the combined hash matches
        const elementValueHash = valueHash(proved.value);
        const combinedHash = combineHash(elementValueHash, lowerHash);

        if (!hashEquals(combinedHash, proved.proof)) {
          throw new GroveDBVerificationError(
            `Lower layer hash mismatch at path ${pathToString(newPath)}: ` +
            `expected ${hashToHex(proved.proof)}, got ${hashToHex(combinedHash)}`
          );
        }
      } else {
        // Element doesn't have subtrees but has a lower layer - error
        throw new GroveDBVerificationError(
          `Proof has lower layer for non-tree element at ${pathToString([...currentPath, proved.key])}`
        );
      }
    } else if (proved.value) {
      // Leaf value - add to results
      let element: Element | null = null;
      if (deserializeElements) {
        try {
          element = deserializeElement(proved.value);
        } catch (e) {
          // If deserialization fails, treat as opaque bytes
          element = null;
        }
      }

      results.push({
        path: currentPath,
        key: proved.key,
        value: proved.value,
        element
      });
    }
  }

  return merkResult.rootHash;
}

/**
 * Verify that a proof matches an expected root hash
 *
 * @param proofBytes - The bincode-encoded GroveDBProof
 * @param expectedRootHash - The expected root hash (from light client)
 * @param options - Verification options
 * @returns Verification result if valid, throws if invalid
 */
export function verifyProofAgainstRoot(
  proofBytes: Uint8Array,
  expectedRootHash: CryptoHash,
  options: VerifyOptions = {}
): GroveDBVerificationResult {
  const result = verifyGroveDBProof(proofBytes, options);

  if (!hashEquals(result.rootHash, expectedRootHash)) {
    throw new GroveDBVerificationError(
      `Root hash mismatch: expected ${hashToHex(expectedRootHash)}, got ${hashToHex(result.rootHash)}`
    );
  }

  return result;
}

/**
 * Convert a path to a human-readable string
 */
function pathToString(path: Uint8Array[]): string {
  return '/' + path.map(p => {
    // Try to decode as UTF-8, fall back to hex
    try {
      const str = new TextDecoder('utf-8', { fatal: true }).decode(p);
      if (/^[\x20-\x7e]+$/.test(str)) {
        return str;
      }
    } catch {}
    return bytesToHex(p);
  }).join('/');
}

/**
 * Quick verification - just check if proof is valid and return root hash
 * Does not parse elements or return results
 */
export function quickVerify(proofBytes: Uint8Array): CryptoHash {
  const proof = decodeGroveDBProof(proofBytes);
  return quickVerifyLayer(proof.proof.rootLayer);
}

/**
 * Quick verify a single layer
 */
function quickVerifyLayer(layerProof: LayerProof): CryptoHash {
  const merkResult = executeMerkProofWithQuery(layerProof.merkProof, null, true);

  // Verify any lower layers
  for (const [keyHex, lowerLayer] of layerProof.lowerLayers) {
    const proved = merkResult.resultSet.find(r => bytesToHex(r.key) === keyHex);
    if (!proved || !proved.value) {
      throw new GroveDBVerificationError(
        `Lower layer key ${keyHex} not found in Merk proof`
      );
    }

    const lowerHash = quickVerifyLayer(lowerLayer);
    const elementValueHash = valueHash(proved.value);
    const combinedHash = combineHash(elementValueHash, lowerHash);

    if (!hashEquals(combinedHash, proved.proof)) {
      throw new GroveDBVerificationError(
        `Lower layer hash mismatch for key ${keyHex}`
      );
    }
  }

  return merkResult.rootHash;
}
