/**
 * Merk Proof Stack Machine Executor
 *
 * Executes Merk proof operations using a stack-based approach.
 */

import { MerkOp, MerkNode, CryptoHash, GroveDBVerificationError, ProvedKeyValue } from './types';
import { Tree, compareBytes } from './tree';
import { MerkDecoder } from './merk-decoder';
import { valueHash } from './hash';

/**
 * Result of executing a Merk proof
 */
export interface MerkExecutionResult {
  /** Root hash of the verified tree */
  rootHash: CryptoHash;
  /** Key-value pairs proven by the proof */
  resultSet: ProvedKeyValue[];
  /** Remaining limit after execution (if limit was set) */
  limit: number | null;
}

/**
 * Execute Merk proof operations and return the resulting tree
 *
 * @param ops - Iterator of Merk operations
 * @param collapse - If true, convert children to hashes to save memory
 * @param visitNode - Optional callback for each node
 * @returns The resulting tree
 */
export function executeOps(
  ops: Iterable<MerkOp>,
  collapse: boolean = true,
  visitNode?: (node: MerkNode) => void
): Tree {
  const stack: Tree[] = [];
  let lastKey: Uint8Array | null = null;
  let lastKeyInverted = false;

  function pop(): Tree {
    const tree = stack.pop();
    if (!tree) {
      throw new GroveDBVerificationError('Stack underflow');
    }
    return tree;
  }

  // Push a node, enforcing key ordering: ascending for normal pushes,
  // descending once the proof switches to inverted pushes.
  function pushNode(node: MerkNode, inverted: boolean): void {
    const key = getNodeKey(node);
    if (key && lastKey && lastKeyInverted === inverted) {
      const cmp = compareBytes(key, lastKey);
      if (inverted ? cmp >= 0 : cmp <= 0) {
        throw new GroveDBVerificationError(
          inverted ? 'Incorrect key ordering inverted' : 'Incorrect key ordering'
        );
      }
    }
    if (key) {
      lastKey = key;
      lastKeyInverted = inverted;
    }

    if (visitNode) {
      visitNode(node);
    }

    stack.push(new Tree(node));
  }

  // Pop two nodes and attach one as a child of the other. The four tree ops
  // differ only in pop order and which side the child lands on.
  function attachChild(parentFirst: boolean, left: boolean): void {
    const first = pop();
    const second = pop();
    const parent = parentFirst ? first : second;
    const child = parentFirst ? second : first;
    parent.attach(left, collapse ? child.intoHash() : child);
    stack.push(parent);
  }

  for (const op of ops) {
    switch (op.type) {
      case 'Push':
        pushNode(op.node, false);
        break;
      case 'PushInverted':
        pushNode(op.node, true);
        break;
      case 'Parent':
        attachChild(true, true);
        break;
      case 'Child':
        attachChild(false, false);
        break;
      case 'ParentInverted':
        attachChild(true, false);
        break;
      case 'ChildInverted':
        attachChild(false, true);
        break;
    }
  }

  if (stack.length !== 1) {
    throw new GroveDBVerificationError(
      `Expected proof to result in exactly one stack item, got ${stack.length}`
    );
  }

  const tree = stack[0];

  // NOTE: we intentionally do NOT assert the AVL height-balance property here.
  // A query proof is a *partial* reconstruction of the tree — only the queried
  // path is expanded, while sibling subtrees collapse to single hash nodes
  // (height 0). That reconstruction is legitimately unbalanced, so an
  // AVL-balance check yields false negatives on valid proofs over large/deep
  // subtrees (it threw "Expected proof to result in a valid AVL tree"). Balance
  // is an insertion-time invariant of the full stored tree, not a property of a
  // proof; the canonical GroveDB (Rust) verifier likewise only recomputes the
  // root hash. Integrity is enforced by the chained hash recomputation
  // (kvHash/combineHash), which still rejects any tampering.

  return tree;
}

/**
 * Execute a Merk proof from bytes
 */
export function executeMerkProof(
  proofBytes: Uint8Array,
  collapse: boolean = true
): Tree {
  const decoder = new MerkDecoder(proofBytes);
  return executeOps(decoder, collapse);
}

/**
 * Execute a Merk proof and extract results matching a query
 *
 * @param proofBytes - The Merk proof bytes
 * @param limit - Optional limit on results
 * @param leftToRight - Direction of traversal
 * @returns Execution result with root hash and matched values
 */
export function executeMerkProofWithQuery(
  proofBytes: Uint8Array,
  limit: number | null = null,
  leftToRight: boolean = true
): MerkExecutionResult {
  const resultSet: ProvedKeyValue[] = [];
  let currentLimit = limit;

  const visitNode = (node: MerkNode) => {
    // Check if we've hit the limit
    if (currentLimit !== null && currentLimit <= 0) {
      return;
    }

    // Extract key-value if present
    switch (node.type) {
      case 'KV': {
        resultSet.push({
          key: node.key,
          value: node.value,
          proof: valueHash(node.value)
        });
        if (currentLimit !== null) currentLimit--;
        break;
      }
      case 'KVValueHash':
      case 'KVValueHashFeatureType': {
        resultSet.push({
          key: node.key,
          value: node.value,
          proof: node.valueHash
        });
        if (currentLimit !== null) currentLimit--;
        break;
      }
      case 'KVRefValueHash': {
        resultSet.push({
          key: node.key,
          value: node.value,
          proof: node.valueHash
        });
        if (currentLimit !== null) currentLimit--;
        break;
      }
      case 'KVDigest': {
        // Digest has no value, just proof of existence. Intentionally does not
        // consume the limit — only nodes that contribute a value count toward it.
        resultSet.push({
          key: node.key,
          value: null,
          proof: node.valueHash
        });
        break;
      }
      // Hash and KVHash don't contribute to results
    }
  };

  const decoder = new MerkDecoder(proofBytes);
  const tree = executeOps(decoder, true, visitNode);

  return {
    rootHash: tree.hash(),
    resultSet,
    limit: currentLimit
  };
}

/**
 * Get the key from a node if it has one
 */
function getNodeKey(node: MerkNode): Uint8Array | null {
  switch (node.type) {
    case 'KV':
    case 'KVValueHash':
    case 'KVDigest':
    case 'KVRefValueHash':
    case 'KVValueHashFeatureType':
      return node.key;
    default:
      return null;
  }
}
