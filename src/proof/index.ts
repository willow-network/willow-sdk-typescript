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
 *
 * Binding guarantee: the proven Item bytes are authoritative. A returned
 * document binds only if it is structurally equal to the JSON those bytes
 * decode to — whitespace and object key order are normalized away, but numbers
 * are compared with `Object.is` and must be fidelity-safe (exact safe integers
 * or finite non-integers below 2^53), so `-0`/`0`, `NaN`, and precision-lossy
 * big integers (e.g. 2^53+1) never bind. Numbers outside that range should be
 * carried as strings to bind. A non-JSON stored Item binds only by exact bytes.
 */

import { QueryResponse, DataRecord } from '../types';
import {
  verifyGroveDBProof,
  quickVerify,
  hexToBytes,
  hashToHex,
  isTreeElement,
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

/** A GroveDB path segment: a string (its UTF-8 bytes) or the bytes. */
export type PathSegment = string | Uint8Array;

/**
 * The GroveDB path of a subgrove's data, `["subgroves", subgroveId, "data"]`:
 * the path `POST /query/:subgrove` and `GET /proof/:subgrove/:key` prove at.
 */
export function subgroveDataPath(subgroveId: string): string[] {
  return ['subgroves', subgroveId, 'data'];
}

export interface ProofVerificationResult {
  valid: boolean;
  rootHash?: string;
  error?: string;
}

function textEncode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function encodePath(path: PathSegment[]): Uint8Array[] {
  return path.map((segment) => (typeof segment === 'string' ? textEncode(segment) : segment));
}

function pathLabel(path: PathSegment[]): string {
  return path
    .map((segment) => (typeof segment === 'string' ? segment : `0x${hashToHex(segment)}`))
    .join(', ');
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
 * A number is fidelity-safe when two distinct JSON source tokens cannot parse
 * to it: exact safe integers, and finite non-integers below the 2^53 boundary.
 * `NaN`, `±Infinity`, `-0`, and any integer past `MAX_SAFE_INTEGER` (which
 * `JSON.parse` silently rounds — e.g. 2^53+1 → 2^53) are NOT fidelity-safe.
 */
function isFidelitySafeNumber(n: number): boolean {
  if (Number.isInteger(n)) return Number.isSafeInteger(n) && !Object.is(n, -0);
  return Number.isFinite(n) && Math.abs(n) < 2 ** 53;
}

/**
 * Structural (deep) equality over JSON values, used to bind returned documents
 * to the proven bytes. Whitespace and object key order are normalized away by
 * comparing parsed trees; numbers are compared with `Object.is` (so `-0 !== 0`
 * and `NaN` never matches) and only when both are {@link isFidelitySafeNumber}
 * — a precision-unsafe number on either side is a non-match, so two distinct
 * committed byte sequences can never bind to the same JS value.
 */
function jsonDeepEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== typeof b) return false;
  if (typeof a === 'number') {
    return Object.is(a, b) && isFidelitySafeNumber(a);
  }
  if (a === b) return true;
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
      Object.prototype.hasOwnProperty.call(b as object, k) &&
      jsonDeepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

/**
 * A value the proof commits to: the raw proven Item bytes, decoded as JSON
 * when they parse, otherwise kept as opaque bytes so a non-JSON stored Item
 * (raw blob) can still bind to a returned value by exact bytes.
 */
type ProvenValue =
  | { kind: 'json'; value: unknown }
  | { kind: 'raw'; bytes: Uint8Array };

function decodeProvenValue(raw: Uint8Array): ProvenValue {
  try {
    return { kind: 'json', value: JSON.parse(new TextDecoder().decode(raw)) };
  } catch {
    return { kind: 'raw', bytes: raw };
  }
}

/**
 * Test whether a returned `document` binds to a proven value. JSON-proven
 * bytes bind by structural equality (number fidelity enforced); non-JSON
 * proven bytes bind only when the document is itself raw bytes equal to them
 * (DataRecord documents are JSON, so they never bind to a raw blob).
 */
function documentBindsTo(proven: ProvenValue, document: unknown): boolean {
  if (proven.kind === 'json') return jsonDeepEqual(proven.value, document);
  return document instanceof Uint8Array && bytesEqual(proven.bytes, document);
}

/**
 * The bytes a proven result commits to as a value: an Item's payload, or the
 * raw leaf bytes when the element didn't deserialize. A subtree is not a
 * value (and one proven without its lower layer is not bound byte for byte),
 * so it gives none.
 */
function provenRaw(result: GroveDBVerificationResult['results'][number]): Uint8Array | null {
  if (result.tree) return null;
  if (result.element?.type === 'Item') return result.element.value;
  if (result.element && isTreeElement(result.element)) return null;
  return result.value;
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
 * Verify a query/range proof and return the computed root hash (hex).
 *
 * Every entry in `documents` must deep-equal a value the proof commits to;
 * a valid proof paired with unrelated documents is rejected. Pass the path
 * the query was made at (`options.path`, e.g. {@link subgroveDataPath}) to
 * bind them to values proven there: without it, a value proven at any path
 * binds. The caller must compare the returned root to a trusted root hash to
 * establish that the proven state is canonical.
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
 * value binding and check only the (key, path) and root.
 */
export async function verifyItemProof(
  proofHex: string,
  key: string,
  value: unknown,
  path: PathSegment[] = [],
  options?: ProofVerificationOptions,
): Promise<string> {
  const bytes = decodeProofBytes(proofHex);

  const expectedKey = textEncode(key);
  const expectedPath = encodePath(path);
  // A non-empty path is required to descend; `[]` (a root-level item) keeps
  // the legacy behaviour and is checked only through the result match below.
  const verification = verifyGroveDBProof(
    bytes,
    expectedPath.length > 0 ? { expectedPath } : {},
  );

  const match = verification.results.find(
    (r) => pathEqual(r.path, expectedPath) && bytesEqual(r.key, expectedKey),
  );
  if (!match) {
    throw new Error(`Proof does not contain key "${key}" at path [${pathLabel(path)}]`);
  }

  if (value !== undefined) {
    const raw = provenRaw(match);
    if (!raw || !documentBindsTo(decodeProvenValue(raw), value)) {
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
 * Verify the proof attached to a `QueryResponse`, binding its documents. Pass
 * the queried path in `options.path` (for `POST /query/:subgrove`,
 * {@link subgroveDataPath}`(subgrove)`) to bind them to that subgrove's data;
 * see {@link verifyQueryProof}.
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
