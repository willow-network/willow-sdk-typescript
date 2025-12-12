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

  for (const op of ops) {
    switch (op.type) {
      case 'Push': {
        // Verify key ordering (ascending)
        const key = getNodeKey(op.node);
        if (key && lastKey && !lastKeyInverted) {
          if (compareBytes(key, lastKey) <= 0) {
            throw new GroveDBVerificationError('Incorrect key ordering');
          }
        }
        if (key) {
          lastKey = key;
          lastKeyInverted = false;
        }

        if (visitNode) {
          visitNode(op.node);
        }

        stack.push(new Tree(op.node));
        break;
      }

      case 'PushInverted': {
        // Verify key ordering (descending for inverted)
        const key = getNodeKey(op.node);
        if (key && lastKey && lastKeyInverted) {
          if (compareBytes(key, lastKey) >= 0) {
            throw new GroveDBVerificationError('Incorrect key ordering inverted');
          }
        }
        if (key) {
          lastKey = key;
          lastKeyInverted = true;
        }

        if (visitNode) {
          visitNode(op.node);
        }

        stack.push(new Tree(op.node));
        break;
      }

      case 'Parent': {
        // Pop parent and child, attach child as LEFT of parent
        const parent = pop();
        const child = pop();
        // Capture height before potential collapse
        const childHeight = child.height;
        const childToAttach = collapse ? child.intoHash() : child;
        parent.attachWithHeight(true, childToAttach, childHeight);
        stack.push(parent);
        break;
      }

      case 'Child': {
        // Pop child and parent, attach child as RIGHT of parent
        const child = pop();
        const parent = pop();
        const childHeight = child.height;
        const childToAttach = collapse ? child.intoHash() : child;
        parent.attachWithHeight(false, childToAttach, childHeight);
        stack.push(parent);
        break;
      }

      case 'ParentInverted': {
        // Pop parent and child, attach child as RIGHT of parent
        const parent = pop();
        const child = pop();
        const childHeight = child.height;
        const childToAttach = collapse ? child.intoHash() : child;
        parent.attachWithHeight(false, childToAttach, childHeight);
        stack.push(parent);
        break;
      }

      case 'ChildInverted': {
        // Pop child and parent, attach child as LEFT of parent
        const child = pop();
        const parent = pop();
        const childHeight = child.height;
        const childToAttach = collapse ? child.intoHash() : child;
        parent.attachWithHeight(true, childToAttach, childHeight);
        stack.push(parent);
        break;
      }
    }
  }

  if (stack.length !== 1) {
    throw new GroveDBVerificationError(
      `Expected proof to result in exactly one stack item, got ${stack.length}`
    );
  }

  const tree = stack[0];

  // Verify AVL tree property
  const heightDiff = Math.abs(tree.childHeights[0] - tree.childHeights[1]);
  if (heightDiff > 1) {
    throw new GroveDBVerificationError('Expected proof to result in a valid AVL tree');
  }

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
        // Digest has no value, just proof of existence
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
