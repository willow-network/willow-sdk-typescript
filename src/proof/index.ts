/**
 * Proof verification for Willow query results.
 *
 * Delegates to the pure-TypeScript GroveDB verifier in src/grovedb/. Every
 * exported function performs full cryptographic verification — no heuristics —
 * and *binds the returned data to the proof*: documents that the proof does
 * not commit to are rejected, so a server cannot pair a valid proof with
 * unrelated data. The returned root hash must still be compared against a
 * trusted source (e.g. a light client's verified block header) to establish
 * that the proven state is the canonical one.
 */

import { QueryResponse, DataRecord } from '../types';
import {
  verifyGroveDBProof,
  quickVerify,
  hexToBytes,
  hashToHex,
  GroveDBVerificationResult,
} from '../grovedb';

export interface ProofVerificationOptions {
  /**
   * Optional expected root hash (hex). When set, `verifyQueryProof` and
   * `verifyItemProof` will throw if the computed root does not match. For
   * trustless operation, prefer obtaining the expected root from a light
   * client rather than hardcoding it here.
   */
  expectedRootHash?: string;
}

export interface ProofVerificationResult {
  valid: boolean;
  rootHash?: string;
  error?: string;
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

function normalizeRoot(hex: string): string {
  return hex.toLowerCase().replace(/^0x/, '');
}

function enforceExpectedRoot(computed: string, expected?: string): void {
  if (!expected) return;
  if (normalizeRoot(computed) !== normalizeRoot(expected)) {
    throw new Error(`Root hash mismatch: computed=${computed}, expected=${expected}`);
  }
}

/**
 * Structural (deep) equality over JSON values.
 */
function jsonDeepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => jsonDeepEqual(v, b[i]));
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a as object);
    const kb = Object.keys(b as object);
    if (ka.length !== kb.length) return false;
    return ka.every((k) =>
      jsonDeepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

/**
 * Collect the JSON values the proof actually commits to (proven Item element
 * payloads that parse as JSON).
 */
function provenJsonValues(verification: GroveDBVerificationResult): unknown[] {
  const values: unknown[] = [];
  for (const result of verification.results) {
    const raw = result.element?.type === 'Item' ? result.element.value : result.value;
    if (!raw) continue;
    try {
      values.push(JSON.parse(new TextDecoder().decode(raw)));
    } catch {
      // Non-JSON payloads can't bind to DataRecord documents; skip.
    }
  }
  return values;
}

/**
 * Require every returned document to deep-equal a value the proof commits to.
 */
function bindDocumentsToProof(
  verification: GroveDBVerificationResult,
  documents: DataRecord[],
): void {
  if (documents.length === 0) return;
  const proven = provenJsonValues(verification);
  for (let i = 0; i < documents.length; i++) {
    if (!proven.some((v) => jsonDeepEqual(v, documents[i]))) {
      throw new Error(
        `Document at index ${i} is not committed by the proof — ` +
          'the server returned data the proof does not cover',
      );
    }
  }
}

/**
 * Verify a query/range proof and return the computed root hash (hex).
 *
 * Every entry in `documents` must deep-equal a value the proof commits to;
 * a valid proof paired with unrelated documents is rejected. The caller must
 * compare the returned root to a trusted root hash to establish that the
 * proven state is canonical.
 */
export async function verifyQueryProof(
  proofHex: string,
  documents: DataRecord[],
  options?: ProofVerificationOptions,
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const result = verifyGroveDBProof(bytes);
  bindDocumentsToProof(result, documents);
  const computed = hashToHex(result.rootHash);
  enforceExpectedRoot(computed, options?.expectedRootHash);
  return computed;
}

/**
 * Verify a single-item proof and return the computed root hash (hex).
 *
 * Beyond computing the root, this enforces that the proof actually contains
 * the requested `key` at the given `path` — rejecting proofs that are
 * internally valid but prove a different (key, path) within the same state
 * tree — and, when `value` is provided, that the proven payload deep-equals
 * it.
 */
export async function verifyItemProof(
  proofHex: string,
  key: string,
  value: unknown,
  path: string[] = [],
  options?: ProofVerificationOptions,
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const verification = verifyGroveDBProof(bytes);

  const expectedKey = textEncode(key);
  const expectedPath = path.map((segment) => textEncode(segment));

  const match = verification.results.find(
    (r) => pathEqual(r.path, expectedPath) && bytesEqual(r.key, expectedKey),
  );
  if (!match) {
    throw new Error(`Proof does not contain key "${key}" at path [${path.join(', ')}]`);
  }

  if (value !== undefined && value !== null) {
    const raw = match.element?.type === 'Item' ? match.element.value : match.value;
    let proven: unknown;
    try {
      proven = raw ? JSON.parse(new TextDecoder().decode(raw)) : undefined;
    } catch {
      proven = undefined;
    }
    if (proven === undefined || !jsonDeepEqual(proven, value)) {
      throw new Error(
        `Proven value for key "${key}" does not match the returned data — ` +
          'the server returned data the proof does not cover',
      );
    }
  }

  const computed = hashToHex(verification.rootHash);
  enforceExpectedRoot(computed, options?.expectedRootHash);
  return computed;
}

/**
 * Fully verify a proof and return its root hash (hex). This performs the
 * same cryptographic checks as `verifyQueryProof` — it does not skip
 * verification — but binds no documents.
 */
export async function computeProofRootHash(proofHex: string): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const root = quickVerify(bytes);
  return hashToHex(root);
}

/**
 * @deprecated Renamed — use {@link computeProofRootHash}. Same behaviour
 * (full verification; the old name suggested it merely parsed the proof).
 */
export const extractRootHashFromProof = computeProofRootHash;

/**
 * Verify the proof attached to a `QueryResponse`, binding its documents.
 */
export async function verifyQueryResponse(response: QueryResponse): Promise<string> {
  if (!response.proof) {
    throw new Error('Query response does not contain proof data');
  }
  return verifyQueryProof(response.proof, response.documents);
}

/**
 * Stateful GroveDB proof verifier that binds `ProofVerificationOptions` at
 * construction time. Mirrors the Python SDK's `GroveDBProofVerifier`, and
 * returns structured `ProofVerificationResult`s instead of throwing.
 *
 * For the simpler throwing API, use the module functions directly
 * (`verifyQueryProof`, `verifyItemProof`, `computeProofRootHash`).
 */
export class GroveDBProofVerifier {
  constructor(public readonly options: ProofVerificationOptions = {}) {}

  /**
   * Verify a query/range proof, binding `documents` to it.
   */
  async verifyQueryProof(
    proofHex: string,
    documents: DataRecord[],
  ): Promise<ProofVerificationResult> {
    try {
      const rootHash = await verifyQueryProof(proofHex, documents, this.options);
      return { valid: true, rootHash };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Verify a single-item proof, binding `key`, `value`, and `path` to it.
   */
  async verifyItemProof(
    proofHex: string,
    key: string,
    value: unknown,
    path: string[] = [],
  ): Promise<ProofVerificationResult> {
    try {
      const rootHash = await verifyItemProof(proofHex, key, value, path, this.options);
      return { valid: true, rootHash };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Fully verify a proof and return its root hash. Throws on malformed
   * proofs — use `verifyQueryProof` for the structured-result variant.
   */
  async extractRootHash(proofHex: string): Promise<string> {
    return computeProofRootHash(proofHex);
  }
}

/**
 * @deprecated Use {@link GroveDBProofVerifier}, which carries options on the
 * instance and returns the same structured result.
 */
export async function verifyProofAdvanced(
  proofHex: string,
  documents: DataRecord[],
  options: ProofVerificationOptions = {},
): Promise<ProofVerificationResult> {
  return new GroveDBProofVerifier(options).verifyQueryProof(proofHex, documents);
}
