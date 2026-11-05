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
  Element,
  MerkNode,
  NULL_HASH
} from './types';
import { bytesToHex, hexToBytes } from './bincode';
import { decodeGroveDBProof } from './decoder';
import { executeMerkProof, executeMerkProofWithQuery } from './executor';
import { deserializeElement, isTreeElement, hasRootKey } from './element';
import { combineHash, valueHash, hashEquals, hashToHex } from './hash';
import { Tree, compareBytes } from './tree';

/**
 * One entry a proof proves: a key at a path and what the proof binds to it.
 */
export interface ProvenEntry {
  path: Uint8Array[];
  key: Uint8Array;
  /**
   * The element bytes the proof binds to the key (for a reference, the
   * referenced element's). `null` for a non-empty subtree proven without its
   * lower layer: its value hash is `combine_hash(value_hash(bytes), subtree
   * root)`, which its bytes alone can't re-derive, so the proof binds no bytes
   * to it and none are given.
   */
  value: Uint8Array | null;
  /**
   * The element `value` decodes to, when `deserializeElements` is set (the
   * default) and `value` is given; otherwise `null`.
   */
  element: Element | null;
  /**
   * The proof gives this entry as a subtree, not a value (the verifier always
   * sets it). A subtree binds no value: when `value` is `null` the proof
   * shows only that the key is present.
   */
  tree?: boolean;
  /**
   * The merk node the proof gives this entry as (the verifier always sets
   * it): grovedb proves an Item as `KV`, a subtree as `KVValueHash`, and a
   * reference as `KVRefValueHash`, whose `value` is the referenced element's
   * bytes, not the reference's.
   */
  nodeType?: MerkNode['type'];
}

/**
 * Result of verifying a GroveDB proof
 */
export interface GroveDBVerificationResult {
  /** Root hash of the entire GroveDB tree */
  rootHash: CryptoHash;
  /**
   * The entries the proof reveals, with their paths. A proof can leave any
   * other entry out (as a `Hash` or `KVHash` node), so these are not every
   * entry under a path: {@link verifyCompleteLayer} checks that a proof
   * reveals a whole subtree.
   */
  results: ProvenEntry[];
}

/**
 * Options for proof verification
 */
export interface VerifyOptions {
  /** Maximum number of results to return */
  limit?: number;
  /** Whether to deserialize element values */
  deserializeElements?: boolean;
  /**
   * The GroveDB path the query was made at. When set, the proof envelope must
   * carry a lower layer for every segment, and no lower layer off the path
   * (see `checkEnvelope`), or end at a subtree on the path that it proves
   * empty; without it an empty result set at that path cannot be told apart
   * from a proof whose subtree was silently dropped.
   */
  expectedPath?: Uint8Array[];
}

/**
 * The check grovedb's own verifier does not make. The verifier finds the next
 * layer by the envelope's `lower_layers` map KEY, which is not hash-bound: a
 * prover who renames or drops the entry for a subtree on the query path gets
 * the same root hash with that subtree's results silently gone, so a proof of
 * "K = V" verifies as "K is absent". Requiring a layer for every path segment
 * closes it (once a layer is present its root is hash-bound to the parent).
 *
 * A proof of a query at a path carries, above the path, only the layer of the
 * path's next segment, and none below it. A lower layer off the path is
 * refused: it would carry entries proven at another path (another
 * subgrove's data, say) beside the queried one.
 *
 * `prove_options` is prover-chosen bytes that steer limit accounting, so it is
 * pinned to the default the chain's prover uses.
 */
export function checkEnvelope(proof: GroveDBProof, expectedPath: Uint8Array[]): void {
  checkHeader(proof);
  const depth = envelopeDepth(proof, expectedPath);
  if (depth < expectedPath.length) throw noLowerLayer(expectedPath, depth);
}

function checkHeader(proof: GroveDBProof): void {
  if (proof.version !== 0) {
    throw new GroveDBVerificationError(`Unsupported proof version: ${proof.version}`);
  }
  checkProveOptions(proof);
}

function checkProveOptions(proof: GroveDBProof): void {
  if (!proof.proof.proveOptions.decreaseLimitOnEmptySubQueryResult) {
    throw new GroveDBVerificationError('envelope: non-default prove_options');
  }
}

/**
 * How many segments of `expectedPath` the envelope descends: the path's
 * length, or the segment whose lower layer it stops before. Refuses a lower
 * layer off the path, and any lower layer below it.
 */
function envelopeDepth(proof: GroveDBProof, expectedPath: Uint8Array[]): number {
  let layer: LayerProof = proof.proof.rootLayer;
  for (let i = 0; i < expectedPath.length; i++) {
    const segment = bytesToHex(expectedPath[i]);
    for (const keyHex of layer.lowerLayers.keys()) {
      if (keyHex !== segment) {
        throw new GroveDBVerificationError(
          `envelope: a lower layer under ${pathToString([...expectedPath.slice(0, i), hexToBytes(keyHex)])}, ` +
            'off the query path'
        );
      }
    }
    const next = layer.lowerLayers.get(segment);
    if (!next) return i;
    layer = next;
  }
  if (layer.lowerLayers.size !== 0) {
    throw new GroveDBVerificationError('envelope: unexpected lower layers below the query path');
  }
  return expectedPath.length;
}

function noLowerLayer(expectedPath: Uint8Array[], i: number): GroveDBVerificationError {
  return new GroveDBVerificationError(
    `envelope: no lower layer for path segment ${i} (${pathToString([expectedPath[i]])}); ` +
      'the proof does not descend to the query path'
  );
}

/**
 * Verify a GroveDB proof and return the root hash and the entries it reveals.
 * It shows that each revealed entry is in the state with that root; it does
 * not show that no other entry is (see {@link verifyCompleteLayer}).
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
  const { rootHash, results } = verifyProof(proof, options);
  return { rootHash, results };
}

/**
 * Verify a decoded GroveDB proof. `depth` is how far it descends along
 * `options.expectedPath`: short of the path's length only when it ends at a
 * subtree on the path that it proves empty.
 */
function verifyProof(
  proof: GroveDBProof,
  options: VerifyOptions
): GroveDBVerificationResult & { depth: number | null } {
  checkHeader(proof);
  const expectedPath = options.expectedPath;
  const depth = expectedPath ? envelopeDepth(proof, expectedPath) : null;

  const results: ProvenEntry[] = [];
  const emptyTrees = new Set<string>();

  const rootHash = verifyLayerProof(
    proof.proof.rootLayer,
    [],
    results,
    emptyTrees,
    options.limit ?? null,
    options.deserializeElements ?? true
  );

  // A proof that stops before the end of the path must prove the subtree it
  // stops at empty: then there is nothing under it to return.
  if (expectedPath && depth !== null && depth < expectedPath.length) {
    if (!emptyTrees.has(entryId(expectedPath.slice(0, depth), expectedPath[depth]))) {
      throw noLowerLayer(expectedPath, depth);
    }
  }

  return { rootHash, results, depth };
}

/** A path and key as one string, to look an entry up by. */
function entryId(path: Uint8Array[], key: Uint8Array): string {
  return [...path, key].map((p) => bytesToHex(p)).join('/');
}

/**
 * Deserialize an element, treating undecodable values as opaque bytes.
 */
function tryDeserializeElement(value: Uint8Array): Element | null {
  try {
    return deserializeElement(value);
  } catch {
    return null;
  }
}

/** How a surfaced leaf's bytes are bound to the proof. */
type LeafBinding =
  /** Its bytes are bound (an item, a reference, or a value-hash-checked leaf). */
  | 'bound'
  /** An empty subtree: its value hash re-derives from its bytes and an empty root. */
  | 'emptyTree'
  /** A non-empty subtree without its lower layer: its bytes are not bound. */
  | 'unboundTree';

/**
 * Bind a surfaced leaf value to the proof that committed it.
 *
 * For KVValueHash / KVValueHashFeatureType nodes the node hash is
 * kv_digest_to_kv_hash(key, valueHash) — the value bytes never enter the root.
 * A server can therefore re-encode an honest leaf as one of these variants with
 * a forged `value` but the real `valueHash`, producing a byte-identical root
 * while surfacing the forged value. Re-derive valueHash(value) and require it to
 * match. KV self-binds (its value enters kv_hash), and KVRefValueHash binds its
 * value via combine_hash(valueHash, value_hash(value)) inside the node hash, so
 * neither needs an extra check.
 *
 * A tree element (Tree, SumTree, BigSumTree, CountTree, CountSumTree) is the
 * exception: its value hash is combine_hash(value_hash(bytes), subtree root)
 * (merk's layered value hash). An empty subtree's root is the null hash, so its
 * value hash is re-derived and checked. A non-empty one's can't be without its
 * lower layer (no subquery on it, an exhausted limit), and grovedb returns
 * such proofs: its bytes are not bound, and it is surfaced as a subtree with
 * no bytes. The element must decode with no trailing bytes, so other bytes
 * can't pass as a tree.
 */
function bindLeafValue(proved: ProvedKeyValue, element: Element | null): LeafBinding {
  if (
    proved.value &&
    (proved.nodeType === 'KVValueHash' || proved.nodeType === 'KVValueHashFeatureType')
  ) {
    if (element && isTreeElement(element)) {
      if (hasRootKey(element)) return 'unboundTree';
      const layered = combineHash(valueHash(proved.value), NULL_HASH);
      if (!hashEquals(layered, proved.proof)) {
        throw new GroveDBVerificationError(
          `Empty subtree does not hash to its committed valueHash: ` +
          `expected ${hashToHex(proved.proof)}, got ${hashToHex(layered)}`
        );
      }
      return 'emptyTree';
    }
    const computed = valueHash(proved.value);
    if (!hashEquals(computed, proved.proof)) {
      throw new GroveDBVerificationError(
        `Leaf value does not hash to its committed valueHash: ` +
        `expected ${hashToHex(proved.proof)}, got ${hashToHex(computed)}`
      );
    }
  }
  return 'bound';
}

/**
 * Verify a layer proof recursively
 *
 * @param layerProof - The layer proof to verify
 * @param currentPath - Current path in the tree
 * @param results - Accumulator for proven values
 * @param emptyTrees - Accumulator for the entries proven to be empty subtrees
 * @param limit - Maximum results (null for unlimited)
 * @param deserializeElements - Whether to parse element bytes
 * @returns Root hash of this layer
 */
function verifyLayerProof(
  layerProof: LayerProof,
  currentPath: Uint8Array[],
  results: ProvenEntry[],
  emptyTrees: Set<string>,
  limit: number | null,
  deserializeElements: boolean
): CryptoHash {
  // Execute the Merk proof to get root hash and values
  const merkResult = executeMerkProofWithQuery(
    layerProof.merkProof,
    limit,
    true // left to right
  );

  // grovedb puts a lower layer only under a key this layer proves with a value.
  for (const keyHex of layerProof.lowerLayers.keys()) {
    if (!merkResult.valueKeys.has(keyHex)) {
      throw new GroveDBVerificationError(
        `Proof has a lower layer under ${pathToString([...currentPath, hexToBytes(keyHex)])}, ` +
          'a key this layer does not prove'
      );
    }
  }

  // Process each proven value
  for (const proved of merkResult.resultSet) {
    // Check if this key has a lower layer proof (subtree)
    const keyHex = bytesToHex(proved.key);
    const lowerLayer = layerProof.lowerLayers.get(keyHex);

    if (lowerLayer && proved.value) {
      // This is a subtree - verify the lower layer. The element is read here
      // whatever `deserializeElements` says: only a tree can have one.
      const element = tryDeserializeElement(proved.value);

      // Only recurse if element is a tree type with a root key
      if (element && isTreeElement(element) && hasRootKey(element)) {
        const newPath = [...currentPath, proved.key];

        // Recursively verify the lower layer
        const lowerHash = verifyLayerProof(
          lowerLayer,
          newPath,
          results,
          emptyTrees,
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
      // Leaf value - bind the bytes to their committed valueHash, then add.
      // The element is read whatever `deserializeElements` says, to tell a
      // subtree from a value.
      const element = tryDeserializeElement(proved.value);
      const binding = bindLeafValue(proved, element);
      if (binding === 'emptyTree') emptyTrees.add(entryId(currentPath, proved.key));
      const bound = binding !== 'unboundTree';
      results.push({
        path: currentPath,
        key: proved.key,
        value: bound ? proved.value : null,
        element: bound && deserializeElements ? element : null,
        tree: element !== null && isTreeElement(element),
        nodeType: proved.nodeType
      });
    }
  }

  return merkResult.rootHash;
}

/**
 * Verify a proof that `key` is absent under `path`, and return its root hash
 * (to compare against a trusted root).
 *
 * The proof must descend to `path` with no lower layer off it, as
 * {@link checkEnvelope} requires, or end at a subtree on the path that it
 * proves empty (nothing is under it). At `path`, the merk proof must show
 * where `key` falls in key order with nothing unrevealed there: the proven
 * keys on either side of it adjacent in the tree, or `key` before the first
 * node or after the last with nothing beyond it. A pruned subtree or a node
 * with a hidden key in that place could hold `key`, so either is refused.
 *
 * @throws GroveDBVerificationError when the proof is invalid, or doesn't prove
 *   `key` absent at `path` (including when `key` is present).
 */
export function verifyKeyAbsence(
  proofBytes: Uint8Array,
  path: Uint8Array[],
  key: Uint8Array
): CryptoHash {
  const proof = decodeGroveDBProof(proofBytes);
  const { rootHash, depth } = verifyProof(proof, { expectedPath: path });
  if (depth !== null && depth < path.length) return rootHash;

  let layer: LayerProof = proof.proof.rootLayer;
  for (const segment of path) layer = layer.lowerLayers.get(bytesToHex(segment))!;
  if (!merkProvesAbsent(executeMerkProof(layer.merkProof, false), key)) {
    throw new GroveDBVerificationError(
      `The proof does not prove ${pathToString([...path, key])} absent`
    );
  }
  return rootHash;
}

/** One node of a subtree a proof reveals whole: its key and what it holds. */
export interface CompleteEntry {
  key: Uint8Array;
  /**
   * The element bytes, bound to the proof. For a reference, the referenced
   * element's bytes (the reference itself is not revealed).
   */
  value: Uint8Array;
  /** The element `value` decodes to, or `null` when it does not decode. */
  element: Element | null;
  /** The node is a reference (a `KVRefValueHash` node). */
  reference: boolean;
}

/** The proof of a whole subtree: its root hash and every node in it. */
export interface CompleteLayer {
  rootHash: CryptoHash;
  /** Every node of the subtree at the path, in key order. */
  entries: CompleteEntry[];
}

/**
 * Verify a proof that reveals the whole subtree at `path`, and return every
 * node in it in key order with the bytes the proof binds to it.
 *
 * The proof must descend to `path` as {@link checkEnvelope} requires (or end
 * at a subtree on the path that it proves empty: then the subtree has no
 * nodes). At `path`, every node of the merk proof must carry its value: a
 * `Hash` node (a pruned subtree), a `KVHash` node (a hidden key and value),
 * or a `KVDigest` node (a hidden value) could hide entries, so each is
 * refused, as is a non-empty subtree without its lower layer, whose bytes the
 * proof does not bind. With none of them, the nodes are the subtree's every
 * entry. A `range_full` query's proof at the path is of this form.
 *
 * @throws GroveDBVerificationError when the proof is invalid or does not
 *   reveal the whole subtree.
 */
export function verifyCompleteLayer(proofBytes: Uint8Array, path: Uint8Array[]): CompleteLayer {
  const proof = decodeGroveDBProof(proofBytes);
  const { rootHash, depth } = verifyProof(proof, { expectedPath: path });
  if (depth !== null && depth < path.length) return { rootHash, entries: [] };

  let layer: LayerProof = proof.proof.rootLayer;
  for (const segment of path) layer = layer.lowerLayers.get(bytesToHex(segment))!;
  const tree = executeMerkProof(layer.merkProof, false);

  const entries: CompleteEntry[] = [];
  let lastKey: Uint8Array | null = null;
  for (const node of tree.inOrder()) {
    const n = node.node;
    if (n.type === 'Hash' || n.type === 'KVHash' || n.type === 'KVDigest') {
      throw new GroveDBVerificationError(
        `The proof does not reveal the whole subtree at ${pathToString(path)}: ` +
          `it has a ${n.type} node, which can hide entries`
      );
    }
    if (lastKey && compareBytes(n.key, lastKey) <= 0) {
      throw new GroveDBVerificationError(`Keys out of order at ${pathToString(path)}`);
    }
    lastKey = n.key;
    const element = tryDeserializeElement(n.value);
    if (n.type === 'KVValueHash' || n.type === 'KVValueHashFeatureType') {
      const binding = bindLeafValue(
        { key: n.key, value: n.value, proof: n.valueHash, nodeType: n.type },
        element
      );
      if (binding === 'unboundTree') {
        throw new GroveDBVerificationError(
          `The proof does not reveal the whole subtree at ${pathToString(path)}: ` +
            `${pathToString([...path, n.key])} is a subtree without its lower layer, whose bytes it does not bind`
        );
      }
    }
    entries.push({ key: n.key, value: n.value, element, reference: n.type === 'KVRefValueHash' });
  }
  return { rootHash, entries };
}

/**
 * Whether a reconstructed merk tree (children kept, not collapsed) shows `key`
 * absent: its in-order nodes, read as the full tree's in key order, have no
 * node with `key`, and the proven nodes on either side of where it would be
 * are adjacent (no pruned subtree or hidden-key node between them).
 */
function merkProvesAbsent(tree: Tree, key: Uint8Array): boolean {
  const nodes: Tree[] = [];
  const stack: Tree[] = [];
  let current: Tree | null = tree;
  while (current || stack.length > 0) {
    while (current) {
      stack.push(current);
      current = current.left ? current.left.tree : null;
    }
    const node = stack.pop()!;
    nodes.push(node);
    current = node.right ? node.right.tree : null;
  }

  let before = -1;
  let after = nodes.length;
  let lastKey: Uint8Array | null = null;
  for (let i = 0; i < nodes.length; i++) {
    const k = nodes[i].getKey();
    if (!k) continue;
    if (lastKey && compareBytes(k, lastKey) <= 0) return false;
    lastKey = k;
    const c = compareBytes(k, key);
    if (c === 0) return false;
    if (c < 0) before = i;
    else if (after === nodes.length) after = i;
  }
  return after === before + 1;
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
  const provedByKey = new Map(merkResult.resultSet.map(r => [bytesToHex(r.key), r]));
  for (const [keyHex, lowerLayer] of layerProof.lowerLayers) {
    const proved = provedByKey.get(keyHex);
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
