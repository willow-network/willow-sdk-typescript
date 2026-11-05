/**
 * Proof verification for Willow query results.
 *
 * Delegates to the pure-TypeScript GroveDB verifier in src/grovedb/. Every
 * exported function performs full cryptographic verification — no heuristics.
 * What each binds differs:
 *
 * - {@link verifyQuerySelection} verifies a whole `POST /query/:subgrove`
 *   result: the proof reveals the subgrove's entire data tree, and the
 *   returned documents and `total` are exactly what the API's query selects
 *   from it, in order. `client.query` uses it.
 * - {@link verifyQueryProof} and {@link verifyQueryResponse} check
 *   membership only: each returned document is a value the proof proves (at
 *   `options.path`, when given). They do not show that the documents are the
 *   complete result, or the query's result at all: a subset, a duplicate, or
 *   a document the query's filter excludes passes.
 * - {@link verifyItemProof} binds one key's value at a path.
 *
 * Each returns the proof's root hash, which must still be compared against a
 * trusted source (e.g. a light client's root for the proof's block height)
 * to establish that the proven state is the canonical one.
 *
 * Binding guarantee: the proven Item bytes are authoritative. A returned
 * document binds only if it is structurally equal to the JSON those bytes
 * decode to — whitespace and object key order are normalized away, but numbers
 * are compared with `Object.is` and must be ones JavaScript carries exactly:
 * a number whose text has the exact decimal value of the shortest text of the
 * double it parses to (what `JSON.stringify` writes for that double; `1.0` and
 * `1` are one value), and that is not an integer beyond ±(2^53 − 1). So every
 * number JavaScript writes binds (`1.1 * 1.1` is `1.2100000000000002`), while
 * `-0`/`0`, `NaN`, precision-lossy big integers (e.g. 2^53+1), and decimals
 * `JSON.parse` rounds to another value's double (`0.33333333333333331`) never
 * bind. Such numbers should be carried as strings to bind. A non-JSON stored
 * Item binds only by exact bytes.
 */

import { QueryResponse, DataRecord } from '../types';
import {
  verifyGroveDBProof,
  quickVerify,
  hashToHex,
  GroveDBVerificationResult,
} from '../grovedb';
import { PathSegment, decodeProofBytes, encodePath, enforceExpectedRoot } from './shared';
import {
  ProvenValue,
  decodeProvenValue,
  documentBindsTo,
  pathEqual,
  pathLabel,
  provenEntry,
  provenRaw,
  requireValueBinds,
} from './binding';

export { subgroveDataPath } from './shared';
export type { PathSegment } from './shared';
export {
  verifyQuerySelection,
  QueryNotVerifiableError,
  QueryResultNotVerifiableError,
  DEFAULT_QUERY_LIMIT,
} from './query-selection';
export type { QuerySelectionOptions } from './query-selection';

export interface ProofVerificationOptions {
  /**
   * Optional expected root hash (hex). When set, `verifyQueryProof` and
   * `verifyItemProof` will throw if the computed root does not match. For
   * trustless operation, prefer obtaining the expected root from a light
   * client rather than hardcoding it here.
   */
  expectedRootHash?: string;
  /**
   * The GroveDB path the query was made at, each segment a string (sent as
   * its UTF-8 bytes) or bytes: for a subgrove's data,
   * {@link subgroveDataPath}`(id)` (`["subgroves", id, "data"]`). When set,
   * the proof must descend to it (or prove a subtree on it empty) with no
   * lower layer off it, and a document binds only to a value proven at
   * exactly this path. A proof whose subtree was renamed or dropped verifies
   * to the same root with an empty result set, and a proof can carry another
   * path's values beside the queried one at the same root: only the path
   * check tells these apart. Without it, a document binds to a value proven
   * at any path in the proof.
   */
  path?: PathSegment[];
}

export interface ProofVerificationResult {
  valid: boolean;
  rootHash?: string;
  error?: string;
}

/**
 * Collect the values the proof actually commits to from its proven results:
 * with `path`, only those proven at exactly that path.
 */
function provenValues(verification: GroveDBVerificationResult, path?: Uint8Array[]): ProvenValue[] {
  const values: ProvenValue[] = [];
  for (const result of verification.results) {
    if (path && !pathEqual(result.path, path)) continue;
    const raw = provenRaw(result);
    if (!raw) continue;
    values.push(decodeProvenValue(raw));
  }
  return values;
}

/**
 * Require every returned document to bind to a value the proof commits to
 * (at `path`, when given).
 */
function bindDocumentsToProof(
  verification: GroveDBVerificationResult,
  documents: DataRecord[],
  path?: Uint8Array[],
): void {
  if (documents.length === 0) return;
  const proven = provenValues(verification, path);
  for (let i = 0; i < documents.length; i++) {
    if (!proven.some((v) => documentBindsTo(v, documents[i]))) {
      throw new Error(
        `Document at index ${i} is not committed by the proof — ` +
          'the server returned data the proof does not cover',
      );
    }
  }
}

/**
 * Verify a query/range proof, check that each document is a value it proves,
 * and return the computed root hash (hex).
 *
 * This checks membership only. Every entry in `documents` must deep-equal a
 * value the proof commits to, so a valid proof paired with unrelated
 * documents is rejected; but the proof may leave entries out, and nothing
 * ties the documents to a query, so a subset, a duplicate, or a document a
 * query's filter excludes passes. To verify a `POST /query/:subgrove` result
 * as the query's whole result, use {@link verifyQuerySelection}.
 *
 * Pass the path the query was made at (`options.path`, e.g.
 * {@link subgroveDataPath}) to bind the documents to values proven there:
 * without it, a value proven at any path binds. The caller must compare the
 * returned root to a trusted root hash to establish that the proven state is
 * canonical.
 */
export async function verifyQueryProof(
  proofHex: string,
  documents: DataRecord[],
  options?: ProofVerificationOptions,
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);
  const expectedPath = options?.path ? encodePath(options.path) : undefined;
  const result = verifyGroveDBProof(bytes, expectedPath ? { expectedPath } : {});
  bindDocumentsToProof(result, documents, expectedPath);
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
 * tree — and, when `value` is supplied (including JSON `null`), that the proven
 * payload binds to it: JSON values bind by structural equality with number
 * fidelity enforced (see {@link jsonDeepEqual}); a non-JSON stored Item binds
 * by exact bytes (pass a `Uint8Array` as `value`). Pass `undefined` to skip
 * value binding and check only the (key, path) and root. A response field
 * that is missing reads as `undefined` too: to bind a value an API returned,
 * refuse an answer that carries none before calling this (as `getData`
 * does), or it is checked for the key alone.
 */
export async function verifyItemProof(
  proofHex: string,
  key: string,
  value: unknown,
  path: PathSegment[] = [],
  options?: ProofVerificationOptions,
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);

  const expectedPath = encodePath(path);
  // A non-empty path is required to descend; `[]` (a root-level item) keeps
  // the legacy behaviour and is checked only through the result match below.
  const verification = verifyGroveDBProof(
    bytes,
    expectedPath.length > 0 ? { expectedPath } : {},
  );

  const match = provenEntry(verification, expectedPath, new TextEncoder().encode(key));
  if (!match) {
    throw new Error(`Proof does not contain key "${key}" at path [${pathLabel(path)}]`);
  }

  if (value !== undefined) requireValueBinds(key, provenRaw(match), value);

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
 * Verify the proof attached to a `QueryResponse` and check that each document
 * is a value it proves (membership only, as {@link verifyQueryProof}: not
 * that the documents are the query's whole result, which
 * {@link verifyQuerySelection} checks). Pass the queried path in
 * `options.path` (for `POST /query/:subgrove`,
 * {@link subgroveDataPath}`(subgrove)`) to bind them to that subgrove's data.
 */
export async function verifyQueryResponse(
  response: QueryResponse,
  options?: ProofVerificationOptions,
): Promise<string> {
  if (!response.proof) {
    throw new Error('Query response does not contain proof data');
  }
  return verifyQueryProof(response.proof, response.documents, options);
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
   * Verify a query/range proof and check that each document is a value it
   * proves (membership only; see the module function
   * {@link verifyQueryProof}).
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
    path: PathSegment[] = [],
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
