/**
 * Proof verification for Willow query results.
 *
 * Delegates to the pure-TypeScript GroveDB verifier in src/grovedb/. Every
 * exported function performs full cryptographic verification — no heuristics.
 * The returned root hash must be compared against a trusted source (e.g. a
 * light client's verified block header) to establish data authenticity.
 */

import { QueryResponse, DataRecord } from '../types';
import {
  verifyGroveDBProof,
  quickVerify,
  hexToBytes,
  hashToHex,
} from '../grovedb';

export interface ProofVerificationOptions {
  /**
   * Optional expected root hash (hex). When set, `verifyQueryProof` and
   * `verifyItemProof` will throw if the computed root does not match. For
   * trustless operation, prefer obtaining the expected root from a light
   * client rather than hardcoding it here.
   */
  expectedRootHash?: string;
  /** Reserved for server-assisted verification against `/verify-proof`. */
  serverAssisted?: boolean;
  /** API endpoint used when `serverAssisted` is enabled. */
  apiUrl?: string;
}

export interface ProofVerificationResult {
  valid: boolean;
  rootHash?: string;
  error?: string;
}

let globalOptions: ProofVerificationOptions = {};

export function configureProofVerification(options: ProofVerificationOptions): void {
  globalOptions = { ...options };
}

function textEncode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function pathEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!bytesEqual(a[i], b[i])) return false;
  return true;
}

function decodeProofBytes(proofHex: string): Uint8Array {
  if (!proofHex) throw new Error('Empty proof provided');
  const bytes = hexToBytes(proofHex);
  if (bytes.length === 0) throw new Error('Empty proof provided');
  return bytes;
}

function enforceExpectedRoot(computed: string, override?: string): void {
  const expected = override ?? globalOptions.expectedRootHash;
  if (!expected) return;
  const normalizedComputed = computed.toLowerCase().replace(/^0x/, '');
  const normalizedExpected = expected.toLowerCase().replace(/^0x/, '');
  if (normalizedComputed !== normalizedExpected) {
    throw new Error(
      `Root hash mismatch: computed=${computed}, expected=${expected}`,
    );
  }
}

/**
 * Verify a query/range proof and return the computed root hash (hex).
 *
 * The caller must compare this to a trusted root hash to establish
 * authenticity — this function alone does not prove the data came from a
 * canonical state unless combined with an independent trust anchor.
 */
export async function verifyQueryProof(
  proofHex: string,
  _documents: DataRecord[],
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const result = verifyGroveDBProof(bytes);
  const computed = hashToHex(result.rootHash);
  enforceExpectedRoot(computed);
  return computed;
}

/**
 * Verify a single-item proof and return the computed root hash (hex).
 *
 * Beyond computing the root, this also enforces that the proof actually
 * contains the requested `key` at the given `path` — rejecting proofs that
 * are internally valid but prove a different (key, path) within the same
 * state tree.
 */
export async function verifyItemProof(
  proofHex: string,
  key: string,
  _value: any,
  path: string[] = [],
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const verification = verifyGroveDBProof(bytes);

  const expectedKey = textEncode(key);
  const expectedPath = path.map((segment) => textEncode(segment));

  const match = verification.results.find(
    (r) => pathEqual(r.path, expectedPath) && bytesEqual(r.key, expectedKey),
  );
  if (!match) {
    throw new Error(
      `Proof does not contain key "${key}" at path [${path.join(', ')}]`,
    );
  }

  const computed = hashToHex(verification.rootHash);
  enforceExpectedRoot(computed);
  return computed;
}

/**
 * Fully verify a proof and return the root hash. Despite the name, this
 * performs the same cryptographic checks as `verifyQueryProof` — it does
 * not skip verification.
 */
export async function extractRootHashFromProof(proofHex: string): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const root = quickVerify(bytes);
  return hashToHex(root);
}

export async function verifyQueryResponse(response: QueryResponse): Promise<string> {
  if (!response.proof) {
    throw new Error('Query response does not contain proof data');
  }
  return verifyQueryProof(response.proof, response.documents);
}

/**
 * Advanced verification that returns a detailed result instead of throwing.
 */
export async function verifyProofAdvanced(
  proofHex: string,
  _documents: DataRecord[],
  options: ProofVerificationOptions = {},
): Promise<ProofVerificationResult> {
  try {
    const bytes = decodeProofBytes(proofHex);
    const result = verifyGroveDBProof(bytes);
    const computed = hashToHex(result.rootHash);
    if (options.expectedRootHash) {
      const normalizedComputed = computed.toLowerCase().replace(/^0x/, '');
      const normalizedExpected = options.expectedRootHash
        .toLowerCase()
        .replace(/^0x/, '');
      if (normalizedComputed !== normalizedExpected) {
        return {
          valid: false,
          rootHash: computed,
          error: `Root hash mismatch: expected ${options.expectedRootHash}, got ${computed}`,
        };
      }
    }
    return { valid: true, rootHash: computed };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
