/**
 * Proof verification for Willow query results
 * 
 * @module proof
 * 
 * IMPORTANT: See ./grovedb-proof.ts for detailed limitations of proof verification
 * in TypeScript. Key points:
 * - Cannot parse full GroveDB binary format (extracts root hash only)
 * - Server-assisted verification available via /verify-proof endpoint
 * - Still cryptographically secure through consensus root hash comparison
 */

import { QueryResponse, DataRecord } from '../types';
import { GroveDBProofVerifier, ProofVerificationOptions, ProofVerificationResult as GroveDBVerificationResult } from './grovedb-proof';

export interface ProofVerificationResult {
  valid: boolean;
  error?: string;
}

// Re-export types for convenience
export { GroveDBProofVerifier, ProofVerificationOptions };

// Global proof verifier instance
let globalVerifier: GroveDBProofVerifier | null = null;

/**
 * Configure the global proof verifier
 * 
 * @param options - Proof verification options
 */
export function configureProofVerification(options: ProofVerificationOptions): void {
  globalVerifier = new GroveDBProofVerifier(options);
}

/**
 * Get the current proof verifier instance
 */
function getVerifier(): GroveDBProofVerifier {
  if (!globalVerifier) {
    globalVerifier = new GroveDBProofVerifier();
  }
  return globalVerifier;
}

/**
 * Verifies a query proof and computes the root hash
 * 
 * @param proofHex - Hex-encoded proof from query response
 * @param documents - The documents returned in the query
 * @returns Computed root hash if verification succeeds
 */
export async function verifyQueryProof(
  proofHex: string,
  documents: DataRecord[]
): Promise<string> {
  const verifier = getVerifier();

  try {
    const result = await verifier.verifyQueryProof(proofHex, documents);

    if (!result.valid) {
      throw new Error(result.error || 'Proof verification failed');
    }

    if (!result.rootHash) {
      throw new Error('Verification succeeded but no root hash returned');
    }

    return result.rootHash;
  } catch (error) {
    // Log warning about verification method for debugging
    if (error instanceof Error && error.message.includes('local-basic')) {
      console.warn('Using basic local proof verification. For full verification, enable server-assisted mode.');
    }
    throw error;
  }
}

/**
 * Verifies a single item proof and computes root hash
 * 
 * @param proofHex - Hex-encoded proof
 * @param key - The key of the item
 * @param value - The value of the item
 * @param path - Optional path to the item (defaults to empty path)
 * @returns Computed root hash
 */
export async function verifyItemProof(
  proofHex: string,
  key: string,
  value: any,
  path: string[] = []
): Promise<string> {
  const verifier = getVerifier();

  try {
    const result = await verifier.verifyItemProof(proofHex, key, value, path);

    if (!result.valid) {
      throw new Error(result.error || 'Proof verification failed');
    }

    if (!result.rootHash) {
      throw new Error('Verification succeeded but no root hash returned');
    }

    return result.rootHash;
  } catch (error) {
    // Log warning about verification method for debugging
    if (error instanceof Error && error.message.includes('local-basic')) {
      console.warn('Using basic local proof verification. For full verification, enable server-assisted mode.');
    }
    throw error;
  }
}

/**
 * Extension for QueryResponse to add verification method
 */
export async function verifyQueryResponse(
  response: QueryResponse
): Promise<string> {
  if (!response.proof) {
    throw new Error('Query response does not contain proof data');
  }

  return verifyQueryProof(
    response.proof,
    response.documents
  );
}

/**
 * Advanced proof verification with custom options
 * 
 * @param proofHex - Hex-encoded proof
 * @param documents - Documents to verify
 * @param options - Verification options
 * @returns Detailed verification result
 */
export async function verifyProofAdvanced(
  proofHex: string,
  documents: any[],
  options: ProofVerificationOptions = {}
): Promise<GroveDBVerificationResult> {
  const verifier = new GroveDBProofVerifier(options);
  return verifier.verifyQueryProof(proofHex, documents);
}

/**
 * Extract root hash from proof without full verification
 * Useful when you just need the root hash for comparison
 * 
 * @param proofHex - Hex-encoded proof
 * @returns The extracted root hash
 */
export async function extractRootHashFromProof(proofHex: string): Promise<string> {
  const verifier = getVerifier();
  return verifier.extractRootHash(proofHex);
}